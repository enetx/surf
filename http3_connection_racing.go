package surf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/surf/profiles"
	"golang.org/x/net/idna"
)

type (
	ConnectionRacingInfo   = profiles.ConnectionRacingInfo
	ConnectionRacingPolicy = profiles.ConnectionRacingPolicy
)

// ConnectionRacing enables connection-only competition between HTTP/3 and a TCP
// backup. No request headers or body are sent until a connection wins. Disabled
// by default, independently of the selected profile's delay policy.
func (h *HTTP3Settings) ConnectionRacing(enabled bool) *HTTP3Settings {
	h.connectionRacing = enabled
	return h
}

// TCPFallbackDelay replaces the profile's policy with a fixed nonnegative delay.
// Zero starts both handshakes immediately. Enable with ConnectionRacing(true).
func (h *HTTP3Settings) TCPFallbackDelay(delay time.Duration) *HTTP3Settings {
	h.tcpFallbackDelay = new(delay)
	return h
}

// ConnectionRacingPolicy selects a delay from per-origin observations. Nil uses
// Surf's 100ms default. Enable separately with ConnectionRacing(true). This setter
// replaces any fixed delay previously selected with TCPFallbackDelay.
func (h *HTTP3Settings) ConnectionRacingPolicy(policy ConnectionRacingPolicy) *HTTP3Settings {
	h.connectionRacingPolicy = policy
	h.tcpFallbackDelay = nil
	return h
}

type connectionPreconnector interface{ Preconnect(*http.Request) error }

type preparedTCPHTTP1Key struct{}

type connectionRace struct {
	mu      sync.Mutex
	closed  bool
	origins map[string]*connectionRaceOrigin
	flights map[*connectionRaceFlight]struct{}
	wg      sync.WaitGroup
	policy  ConnectionRacingPolicy
	quic    func(context.Context, string) error
	tcp     func(*http.Request) error
}

const maxConnectionRaceOrigins = 256

type connectionRaceOrigin struct {
	flight *connectionRaceFlight
	info   ConnectionRacingInfo
	conn   *quic.Conn
}

type connectionRaceFlight struct {
	done     chan struct{}
	cancel   context.CancelFunc
	waiters  int
	chosen   bool
	protocol int
	err      error
	tcpHTTP1 bool
}

func (r *connectionRace) selectProtocol(req *http.Request, address string) (*connectionRaceFlight, error) {
	if err := req.Context().Err(); err != nil {
		return nil, context.Cause(req.Context())
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, errors.New("surf: connection racer is closed")
	}
	if r.origins == nil {
		r.origins = make(map[string]*connectionRaceOrigin)
		r.flights = make(map[*connectionRaceFlight]struct{})
	}
	origin := r.origins[address]
	if origin == nil {
		origin = &connectionRaceOrigin{info: ConnectionRacingInfo{Origin: "https://" + address}}
		r.origins[address] = origin
	}
	f := origin.flight
	if f == nil {
		ctx, cancel := context.WithCancel(context.WithoutCancel(req.Context()))
		f = &connectionRaceFlight{done: make(chan struct{}), cancel: cancel}
		origin.flight = f
		r.flights[f] = struct{}{}
		// Freeze the preparation request: neither worker owns the application body.
		preparation := req.Clone(ctx)
		preparation.Body, preparation.GetBody = nil, nil
		info := origin.info
		if origin.conn != nil {
			info.SmoothedRTT = origin.conn.ConnectionStats().SmoothedRTT
		}
		r.wg.Add(1)
		go r.run(preparation, address, origin, f, info)
	}
	f.waiters++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		f.waiters--
		if f.waiters == 0 && !f.chosen {
			f.cancel()
			if origin.flight == f {
				origin.flight = nil
			}
		}
		r.mu.Unlock()
	}()
	select {
	case <-req.Context().Done():
		return nil, context.Cause(req.Context())
	case <-f.done:
		if req.Context().Err() != nil {
			return nil, context.Cause(req.Context())
		}
		return f, f.err
	}
}

func (r *connectionRace) run(req *http.Request, address string, origin *connectionRaceOrigin, f *connectionRaceFlight, info ConnectionRacingInfo) {
	defer r.wg.Done()
	defer f.cancel()
	defer func() {
		r.mu.Lock()
		if origin.flight == f {
			origin.flight = nil
		}
		delete(r.flights, f)
		// Pool ownership remains in the transports. Bound only this client's
		// policy history, without evicting another active connection race.
		for len(r.origins) > maxConnectionRaceOrigins {
			removed := false
			for address, cached := range r.origins {
				if cached.flight == nil {
					delete(r.origins, address)
					removed = true
					break
				}
			}
			if !removed {
				break
			}
		}
		r.mu.Unlock()
	}()
	finish := func(protocol int, err error) {
		r.mu.Lock()
		if !f.chosen {
			f.protocol, f.err, f.chosen = protocol, err, true
			close(f.done)
		}
		r.mu.Unlock()
	}
	delay := 100 * time.Millisecond
	if r.policy != nil {
		delay = r.policy(info)
	}
	if delay < 0 {
		finish(0, errors.New("surf: negative TCP fallback delay"))
		return
	}
	qctx, cancelQUIC := context.WithCancel(req.Context())
	defer cancelQUIC()
	tctx, cancelTCP := context.WithCancel(req.Context())
	defer cancelTCP()
	quicDone, tcpDone := make(chan error, 1), make(chan error, 1)
	var workers sync.WaitGroup
	defer workers.Wait()
	workers.Go(func() { quicDone <- r.quic(qctx, address) })
	timer := time.NewTimer(delay)
	defer timer.Stop()
	tcpStarted := false
	startTCP := func() {
		if !tcpStarted {
			tcpStarted = true
			workers.Go(func() {
				tcpDone <- r.tcp(req.WithContext(context.WithValue(tctx, preparedTCPHTTP1Key{}, &f.tcpHTTP1)))
			})
		}
	}
	var quicErr, tcpErr error
	quicFinished, tcpFinished := false, false
	for {
		select {
		case <-req.Context().Done():
			cancelQUIC()
			cancelTCP()
			finish(0, context.Cause(req.Context()))
			return
		case <-timer.C:
			startTCP()
		case err := <-quicDone:
			quicFinished, quicErr = true, err
			r.mu.Lock()
			if err == nil {
				origin.info.QUICWorked = true
				origin.info.LastQUICError = nil
			} else if !errors.Is(err, context.Canceled) {
				origin.info.LastQUICError = err
			}
			r.mu.Unlock()
			if err == nil {
				cancelTCP()
				finish(3, nil)
				return
			}
			startTCP()
		case err := <-tcpDone:
			tcpFinished, tcpErr = true, err
			if err == nil {
				finish(2, nil)
				// Keep the connection-only QUIC attempt in the shared pool after
				// TCP wins. It remains bounded by handshake timeout and Client.Close.
				if quicFinished {
					return
				}
			}
		}
		if quicFinished && tcpFinished {
			finish(0, fmt.Errorf("surf: QUIC and TCP preparation failed: %w", errors.Join(quicErr, tcpErr)))
			return
		}
	}
}

func (r *connectionRace) close(idleOnly bool) {
	r.mu.Lock()
	if !idleOnly {
		r.closed = true
	}
	for f := range r.flights {
		if !idleOnly || f.chosen {
			f.cancel()
		}
	}
	r.mu.Unlock()
	if !idleOnly {
		r.wg.Wait()
	}
}

func (r *connectionRace) observeQUIC(address string, conn *quic.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if origin := r.origins[address]; origin != nil {
		origin.conn = conn
	}
}

func raceAddress(req *http.Request) (string, error) {
	host := req.URL.Hostname()
	if host == "" {
		return "", errors.New("surf: missing connection race host")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		var err error
		host, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return "", err
		}
	}
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port), nil
}

func (ut *uquicTransport) roundTripRacing(req *http.Request) (*http.Response, error) {
	address, err := raceAddress(req)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	selection, err := ut.racer.selectProtocol(req, address)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	// After selection, only the selected normal transport owns the body. Never
	// retry a failed application exchange against the other protocol here.
	if selection.protocol == 3 {
		return ut.roundTripHTTP3(req)
	}
	if selection.tcpHTTP1 {
		req = req.WithContext(context.WithValue(req.Context(), preparedTCPHTTP1Key{}, true))
	}
	return ut.fallbackTransport.RoundTrip(req)
}

func (ut *uquicTransport) preconnectTCP(req *http.Request) error {
	// JA wraps the fallback after the HTTP/3 factory runs. Resolve the current
	// transport at use time, so preparation and sending always use the same TLS.
	preconnect, ok := ut.fallbackTransport.(connectionPreconnector)
	if !ok {
		return errors.New("surf: TCP transport does not support Preconnect")
	}
	return preconnect.Preconnect(req)
}
