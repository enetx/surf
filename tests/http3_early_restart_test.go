package surf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	firefox "github.com/enetx/surf/profiles/firefox/quic"
	"github.com/stretchr/testify/require"
)

type restartObservation struct {
	connection         int32
	method, path, body string
	resumed, early     bool
}

type restartPeer struct {
	url                      string
	roots                    *x509.CertPool
	release                  chan struct{}
	earlySent                chan struct{}
	seen                     chan restartObservation
	closed                   chan struct{}
	connections              atomic.Int32
	firstEarly               sync.Once
	additionalTrace          qlogwriter.Trace
	disableProbeCoalescing   bool
	disableEarlyPeerRecovery bool
	earlyHintRTT             time.Duration
	earlyHintObserver        func(quic.PeerPacketInfo)
	rejectVerification       atomic.Bool
}

func newRestartPeer(t *testing.T, mode string, wrap ...func(net.PacketConn) net.PacketConn) *restartPeer {
	t.Helper()
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	config := cert.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	cert.Close()
	p := &restartPeer{roots: roots, release: make(chan struct{}), earlySent: make(chan struct{}), seen: make(chan restartObservation, 64), closed: make(chan struct{}, 8)}
	closing := make(chan struct{})
	config.NextProtos = []string{"h3"}
	var handshakes atomic.Int32
	config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) == 1 {
			return nil, nil
		}
		select {
		case <-p.earlySent:
		case <-closing:
			return nil, context.Canceled
		case <-info.Context().Done():
			return nil, info.Context().Err()
		}
		select {
		case <-p.release:
		case <-closing:
			return nil, context.Canceled
		case <-info.Context().Done():
			return nil, info.Context().Err()
		}
		if mode == "handshake-error" {
			return nil, errors.New("controlled handshake failure")
		}
		if mode == "hrr" {
			next := config.Clone()
			next.GetConfigForClient = nil
			next.CurvePreferences = []tls.CurveID{tls.CurveP384}
			return next, nil
		}
		return nil, nil
	}
	config.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		if mode == "unknown-ticket" {
			return nil, nil
		}
		state, err := config.DecryptTicket(identity, cs)
		if state != nil && mode != "accept" {
			state.EarlyData = false
		}
		return state, err
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	if len(wrap) > 0 {
		packet = wrap[0](packet)
	}
	listener, err := quic.ListenEarly(packet, config, &quic.Config{Allow0RTT: true})
	require.NoError(t, err)
	p.url = "https://" + packet.LocalAddr().String()
	t.Cleanup(func() { close(closing); listener.Close(); packet.Close() })
	go func() {
		for {
			conn, err := listener.Accept(t.Context())
			if err != nil {
				return
			}
			number := p.connections.Add(1)
			go func() {
				defer func() { conn.CloseWithError(0, ""); p.closed <- struct{}{} }()
				select {
				case <-conn.HandshakeComplete():
				case <-conn.Context().Done():
					return
				}
				capacity, blocked := uint64(4096), uint64(16)
				if number > 1 && mode == "zero-table" {
					capacity, blocked = 0, 0
				}
				settings := g.NewMapOrd[uint64, uint64]()
				settings.Insert(1, capacity)
				settings.Insert(7, blocked)
				server := &http3.Server{AdditionalSettings: settings, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						return
					}
					p.seen <- restartObservation{number, r.Method, r.URL.Path, string(body), r.TLS.DidResume, conn.ConnectionState().Used0RTT}
					io.WriteString(w, "ok")
				})}
				server.ServeQUICConn(conn)
			}()
		}
	}()
	return p
}

func restartClient(t *testing.T, p *restartPeer, enabled bool) *surf.Client {
	t.Helper()
	cache := &h3SessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(8), stored: make(chan struct{}, 32)}
	httpSettings := surf.NewClient().Builder().Proxy("").Impersonate().Firefox().ForceHTTP3().
		HTTP3Settings().EarlyData(true).EarlyDataRestart(enabled).QpackDynamicTable(true).QpackEncoderTableCapacity(4096)
	if p.earlyHintRTT > 0 {
		httpSettings.EarlyDataBackup(false)
	}
	settings := httpSettings.Set().QUICSettings()
	if p.disableProbeCoalescing {
		settings.CoalescePTOProbes(false)
	}
	if p.earlyHintRTT > 0 {
		settings.CachedInitialRTT(0, 0, 0).ResumeVersion(false).ResumeRTT(0).InitialRTT(p.earlyHintRTT)
	}
	if p.disableEarlyPeerRecovery || p.earlyHintRTT > 0 {
		settings.PeerPacketRecoveryPolicy(func(info quic.PeerPacketInfo) quic.PeerPacketRecovery {
			action := firefox.PeerRecovery(info)
			if action.ResendEarlyData && p.earlyHintObserver != nil {
				p.earlyHintObserver(info)
			}
			if p.disableEarlyPeerRecovery {
				action.ResendEarlyData = false
			}
			return action
		})
		if p.disableEarlyPeerRecovery {
			settings.EarlyDataResendOnPeerCrypto(false)
		}
	}
	client := settings.Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		primary := &earlyTrace{streams: make(map[quic.StreamID]bool), onEarly: func() { p.firstEarly.Do(func() { close(p.earlySent) }) }}
		if p.additionalTrace != nil {
			return &pairedRestartTrace{primary: primary, additional: p.additionalTrace}
		}
		return primary
	}).Set().
		TLSConfig(&tls.Config{RootCAs: p.roots, ClientSessionCache: cache, VerifyConnection: func(tls.ConnectionState) error {
			if p.rejectVerification.Load() {
				return errors.New("controlled certificate verification failure")
			}
			return nil
		}}).Timeout(8 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	request, err := http.NewRequest(http.MethodGet, p.url+"/warm", nil)
	require.NoError(t, err)
	response, err := client.GetClient().Do(request)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	require.NoError(t, err)
	<-p.seen
	select {
	case <-cache.stored:
	case <-time.After(5 * time.Second):
		t.Fatal("missing ticket")
	}
	client.CloseIdleConnections()
	<-p.closed
	return client
}

func TestFirefoxEarlyRejectionKeepsQUICConnection(t *testing.T) {
	for _, mode := range []string{"rejected", "unknown-ticket", "hrr", "zero-table"} {
		t.Run(mode, func(t *testing.T) {
			peer := newRestartPeer(t, mode)
			client := restartClient(t, peer, true)
			request, err := http.NewRequest(http.MethodGet, peer.url+"/replay", nil)
			require.NoError(t, err)
			request.Header.Set("x-repeated", strings.Repeat("cached QPACK entry ", 20))
			type result struct {
				response *http.Response
				err      error
			}
			done := make(chan result, 1)
			go func() { r, e := client.GetClient().Do(request); done <- result{r, e} }()
			select {
			case <-peer.earlySent:
			case <-time.After(5 * time.Second):
				t.Fatal("no early request")
			}
			close(peer.release)
			got := <-done
			require.NoError(t, got.err)
			data, err := io.ReadAll(got.response.Body)
			got.response.Body.Close()
			require.NoError(t, err)
			require.Equal(t, "ok", string(data))
			require.NotEmpty(t, got.response.TLS.VerifiedChains)
			seen := <-peer.seen
			require.EqualValues(t, 2, seen.connection)
			require.Equal(t, "/replay", seen.path)
			require.False(t, seen.early)
			require.Equal(t, mode != "unknown-ticket", seen.resumed)
			require.EqualValues(t, 2, peer.connections.Load())
			// Subsequent requests must use the fresh HTTP/3 state on this same conn.
			request, err = http.NewRequest(http.MethodGet, peer.url+"/after", nil)
			require.NoError(t, err)
			response, err := client.GetClient().Do(request)
			require.NoError(t, err)
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			require.EqualValues(t, 2, (<-peer.seen).connection)
			require.EqualValues(t, 2, peer.connections.Load())
		})
	}
}

func TestFirefoxEarlyRestartCancellationAndConcurrency(t *testing.T) {
	for _, cancelOne := range []bool{false, true} {
		t.Run(map[bool]string{false: "parallel", true: "cancel"}[cancelOne], func(t *testing.T) {
			peer := newRestartPeer(t, "rejected")
			client := restartClient(t, peer, true)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, peer.url+"/early", nil)
			require.NoError(t, err)
			first := make(chan error, 1)
			go func() {
				response, err := client.GetClient().Do(request)
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
				first <- err
			}()
			select {
			case <-peer.earlySent:
			case <-time.After(5 * time.Second):
				t.Fatal("missing early request")
			}
			if cancelOne {
				cancel()
				require.ErrorIs(t, <-first, context.Canceled)
			}
			const parallel = 6
			results := make(chan error, parallel)
			for n := range parallel {
				go func() {
					method := http.MethodGet
					var body io.Reader
					if n%3 == 1 {
						method = http.MethodHead
					}
					if n%3 == 2 {
						method = http.MethodPost
						body = strings.NewReader("unsafe body must wait")
					}
					request, err := http.NewRequest(method, peer.url+"/parallel", body)
					if err == nil {
						var response *http.Response
						response, err = client.GetClient().Do(request)
						if err == nil {
							_, err = io.Copy(io.Discard, response.Body)
							response.Body.Close()
						}
					}
					results <- err
				}()
			}
			close(peer.release)
			if !cancelOne {
				require.NoError(t, <-first)
			}
			for range parallel {
				require.NoError(t, <-results)
			}
			count := parallel
			if !cancelOne {
				count++
			}
			for range count {
				seen := <-peer.seen
				require.EqualValues(t, 2, seen.connection)
				require.False(t, seen.early)
				if seen.method == http.MethodPost {
					require.Equal(t, "unsafe body must wait", seen.body)
				}
			}
			require.EqualValues(t, 2, peer.connections.Load())
		})
	}
}

func TestFirefoxEarlyRestartExplicitDisable(t *testing.T) {
	peer := newRestartPeer(t, "rejected")
	client := restartClient(t, peer, false)
	request, err := http.NewRequest(http.MethodGet, peer.url+"/legacy", nil)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		r, err := client.GetClient().Do(request)
		if err == nil {
			_, err = io.Copy(io.Discard, r.Body)
			r.Body.Close()
		}
		done <- err
	}()
	select {
	case <-peer.earlySent:
	case <-time.After(5 * time.Second):
		t.Fatal("no early request")
	}
	close(peer.release)
	require.NoError(t, <-done)
	seen := <-peer.seen
	require.EqualValues(t, 3, seen.connection)
	require.EqualValues(t, 3, peer.connections.Load())
}

func TestFirefoxEarlyRestartDoesNotRetryHandshakeFailure(t *testing.T) {
	peer := newRestartPeer(t, "handshake-error")
	client := restartClient(t, peer, true)
	request, err := http.NewRequest(http.MethodGet, peer.url+"/failed", nil)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := client.GetClient().Do(request); done <- err }()
	select {
	case <-peer.earlySent:
	case <-time.After(5 * time.Second):
		t.Fatal("no early request")
	}
	close(peer.release)
	require.Error(t, <-done)
	require.LessOrEqual(t, peer.connections.Load(), int32(2))
	select {
	case seen := <-peer.seen:
		t.Fatalf("failed handshake delivered request: %+v", seen)
	default:
	}
}

func TestFirefoxEarlyRestartDoesNotBypassVerification(t *testing.T) {
	peer := newRestartPeer(t, "rejected")
	client := restartClient(t, peer, true)
	peer.rejectVerification.Store(true)
	request, err := http.NewRequest(http.MethodGet, peer.url+"/unverified", nil)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, err := client.GetClient().Do(request); done <- err }()
	select {
	case <-peer.earlySent:
	case <-time.After(5 * time.Second):
		t.Fatal("no early request")
	}
	close(peer.release)
	require.ErrorContains(t, <-done, "controlled certificate verification failure")
	select {
	case seen := <-peer.seen:
		t.Fatalf("unverified handshake delivered request: %+v", seen)
	default:
	}
}

// The low-level engine permits explicitly marked early GETs with bodies. Surf's
// normal safe-method policy never opts those bodies into early data itself.
func TestEarlyRestartExplicitBodyRequiresReplayFactory(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(map[bool]string{false: "unreplayable", true: "replayable"}[replay], func(t *testing.T) {
			peer := newRestartPeer(t, "rejected")
			cache := &h3SessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(8), stored: make(chan struct{}, 32)}
			transport := &http3.Transport{EarlyDataRestart: true,
				TLSClientConfig: &tls.Config{RootCAs: peer.roots, ClientSessionCache: cache},
				QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
					return &earlyTrace{streams: make(map[quic.StreamID]bool), onEarly: func() { peer.firstEarly.Do(func() { close(peer.earlySent) }) }}
				}},
			}
			t.Cleanup(func() { transport.Close() })
			request, err := http.NewRequestWithContext(t.Context(), http3.MethodGet0RTT, peer.url+"/warm", nil)
			require.NoError(t, err)
			response, err := transport.RoundTrip(request)
			require.NoError(t, err)
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			<-peer.seen
			select {
			case <-cache.stored:
			case <-time.After(5 * time.Second):
				t.Fatal("missing ticket")
			}
			transport.CloseIdleConnections()
			<-peer.closed
			request, err = http.NewRequestWithContext(t.Context(), http3.MethodGet0RTT, peer.url+"/body", strings.NewReader("explicit early body"))
			require.NoError(t, err)
			closed := make(chan struct{})
			request.Body = &restartBody{Reader: strings.NewReader("explicit early body"), closed: closed}
			if !replay {
				request.GetBody = nil
			}
			done := make(chan error, 1)
			go func() {
				response, err := transport.RoundTrip(request)
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
				done <- err
			}()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("early body was not consumed and closed")
			}
			<-peer.earlySent
			close(peer.release)
			err = <-done
			if replay {
				require.NoError(t, err)
				seen := <-peer.seen
				require.EqualValues(t, 2, seen.connection)
				require.Equal(t, "explicit early body", seen.body)
			} else {
				require.ErrorIs(t, err, quic.Err0RTTRejected)
				select {
				case seen := <-peer.seen:
					t.Fatalf("unreplayable body was replayed: %+v", seen)
				default:
				}
			}
		})
	}
}

type restartBody struct {
	*strings.Reader
	closed chan struct{}
	once   sync.Once
}

func (b *restartBody) Close() error { b.once.Do(func() { close(b.closed) }); return nil }
