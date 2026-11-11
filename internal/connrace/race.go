// Package connrace coordinates connection preparation without sending requests.
package connrace

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/surf/profiles"
)

// Result identifies the prepared transport that owns the application exchange.
type Result struct {
	Protocol int
	HTTP1    bool
}

type tcpPreparation struct {
	http1 bool
	err   error
}

// Racer owns shared connection attempts and per-origin observations.
// Construct it with New. Transports retain ownership of prepared connections.
type Racer struct {
	mu      sync.Mutex
	closed  bool
	origins map[string]*originState
	flights map[*flight]struct{}
	wg      sync.WaitGroup
	policy  profiles.ConnectionRacingPolicy
	quic    func(context.Context, string) error
	tcp     func(*http.Request) (bool, error)
}

const maxOrigins = 256

type originState struct {
	flight *flight
	info   profiles.ConnectionRacingInfo
	conn   *quic.Conn
}

type flight struct {
	done     chan struct{}
	cancel   context.CancelFunc
	waiters  int
	chosen   bool
	protocol int
	err      error
	tcpHTTP1 bool
}

// New retains the supplied policy and connection-only preparation callbacks.
// The TCP callback reports whether preparation selected HTTP/1 instead of HTTP/2.
func New(policy profiles.ConnectionRacingPolicy, quic func(context.Context, string) error, tcp func(*http.Request) (bool, error)) *Racer {
	return &Racer{policy: policy, quic: quic, tcp: tcp}
}

// SelectProtocol shares preparation among waiters, with independent cancellation.
func (r *Racer) SelectProtocol(req *http.Request, address string) (Result, error) {
	if err := req.Context().Err(); err != nil {
		return Result{}, context.Cause(req.Context())
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Result{}, errors.New("surf: connection racer is closed")
	}

	if r.origins == nil {
		r.origins = make(map[string]*originState)
		r.flights = make(map[*flight]struct{})
	}

	origin := r.origins[address]
	if origin == nil {
		origin = &originState{info: profiles.ConnectionRacingInfo{Origin: "https://" + address}}
		r.origins[address] = origin
	}

	f := origin.flight
	if f == nil {
		ctx, cancel := context.WithCancel(context.WithoutCancel(req.Context()))

		f = &flight{done: make(chan struct{}), cancel: cancel}
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
		return Result{}, context.Cause(req.Context())
	case <-f.done:
		if req.Context().Err() != nil {
			return Result{}, context.Cause(req.Context())
		}
		return Result{Protocol: f.protocol, HTTP1: f.tcpHTTP1}, f.err
	}
}

func (r *Racer) run(
	req *http.Request,
	address string,
	origin *originState,
	f *flight,
	info profiles.ConnectionRacingInfo,
) {
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
		for len(r.origins) > maxOrigins {
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

	quicDone := make(chan error, 1)
	tcpDone := make(chan tcpPreparation, 1)

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
				http1, err := r.tcp(req.WithContext(tctx))
				tcpDone <- tcpPreparation{http1: http1, err: err}
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
		case prepared := <-tcpDone:
			err := prepared.err
			f.tcpHTTP1 = prepared.http1
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

// Close cancels selected background attempts, or all attempts when idleOnly is false.
// A full close waits for preparation workers and prevents new races.
func (r *Racer) Close(idleOnly bool) {
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

// ObserveQUIC retains a connection for the next policy call's RTT observation.
func (r *Racer) ObserveQUIC(address string, conn *quic.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if origin := r.origins[address]; origin != nil {
		origin.conn = conn
	}
}
