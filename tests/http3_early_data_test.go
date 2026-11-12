package surf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	transportlog "github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
	"github.com/wzshiming/socks5"
)

type earlyTrace struct {
	mu      sync.Mutex
	streams map[quic.StreamID]bool
	waiters map[quic.StreamID]chan struct{}
	onEarly func()
}

func (r *earlyTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *earlyTrace) Close() error                     { return nil }
func (r *earlyTrace) RecordEvent(event qlogwriter.Event) {
	if sent, ok := event.(transportlog.PacketSent); ok && sent.Header.PacketType == transportlog.PacketType0RTT && r.onEarly != nil {
		for _, frame := range sent.Frames {
			if stream, ok := frame.Frame.(*transportlog.StreamFrame); ok && stream.StreamID == 0 {
				r.onEarly()
			}
		}
	}
	packet, ok := event.(transportlog.PacketReceived)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, frame := range packet.Frames {
		if f, ok := frame.Frame.(*transportlog.StreamFrame); ok {
			r.streams[f.StreamID] = r.streams[f.StreamID] || packet.Header.PacketType == transportlog.PacketType0RTT
			if ready, waiting := r.waiters[f.StreamID]; waiting {
				close(ready)
				delete(r.waiters, f.StreamID)
			}
		}
	}
}

// Stream handling wakes the HTTP/3 handler before the connection records its
// PacketReceived event. Wait for that event instead of treating "not recorded
// yet" as a packet classified as 1-RTT. Map presence records either outcome.
func (r *earlyTrace) waitUsed(ctx context.Context, id quic.StreamID) (bool, error) {
	r.mu.Lock()
	if early, observed := r.streams[id]; observed {
		r.mu.Unlock()
		return early, nil
	}
	if r.waiters == nil {
		r.waiters = make(map[quic.StreamID]chan struct{})
	}
	ready, waiting := r.waiters[id]
	if !waiting {
		ready = make(chan struct{})
		r.waiters[id] = ready
	}
	r.mu.Unlock()
	select {
	case <-ready:
		return r.used(id), nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (r *earlyTrace) used(id quic.StreamID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.streams[id]
}

type earlyObservation struct {
	early, resumed bool
	method         string
}

func earlyDataServer(t *testing.T, reject *atomic.Bool, tooEarly bool, earlySent <-chan struct{}) (string, <-chan earlyObservation) {
	t.Helper()
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsConfig := cert.TLS.Clone()
	cert.Close()
	// Synchronize with the client's emitted request packet. An arbitrary sleep
	// does not establish a 0-RTT opportunity under scheduler/CI load.
	var handshakes atomic.Int32
	tlsConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) == 1 || earlySent == nil {
			return nil, nil
		}
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case <-earlySent:
			return nil, nil
		case <-timer.C:
			return nil, errors.New("client did not emit the eligible 0-RTT request")
		case <-info.Context().Done():
			return nil, info.Context().Err()
		}
	}
	tlsConfig.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		state, err := tlsConfig.DecryptTicket(identity, cs)
		if state != nil && reject.Load() {
			state.EarlyData = false
		}
		return state, err
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	observations := make(chan earlyObservation, 16)
	type connectionKey struct{}
	var calls atomic.Int32
	server := &http3.Server{TLSConfig: tlsConfig, QUICConfig: &quic.Config{Allow0RTT: true, Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return &earlyTrace{streams: make(map[quic.StreamID]bool)}
	}},
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			return context.WithValue(ctx, connectionKey{}, c)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn := r.Context().Value(connectionKey{}).(*quic.Conn)
			_, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				t.Errorf("request body: %v", err)
				return
			}
			streamID := r.Body.(interface{ StreamID() quic.StreamID }).StreamID()
			sentEarly, err := conn.QlogTrace().(*earlyTrace).waitUsed(r.Context(), streamID)
			if err != nil {
				t.Errorf("request packet classification: %v", err)
				return
			}
			observations <- earlyObservation{sentEarly, r.TLS.DidResume, r.Method}
			if tooEarly && calls.Add(1) > 1 {
				w.WriteHeader(425)
				return
			}
			io.WriteString(w, "ok")
		})}
	go server.Serve(pc)
	t.Cleanup(func() { server.Close(); pc.Close() })
	return "https://" + pc.LocalAddr().String(), observations
}

func TestHTTP3EarlyDataResumption(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		enabled, reject, tooEarly bool
		method                    string
	}{
		{"accepted", true, false, false, "GET"}, {"disabled", false, false, false, "GET"}, {"head", true, false, false, "HEAD"},
		{"get-body", true, false, false, "GET"}, {"post", true, false, false, "POST"}, {"rejected", true, true, false, "GET"}, {"425", true, false, true, "GET"},
	} {
		for _, hello := range []string{"native", "coalesced", "datagram-padding", "dedicated", "socks5", "chrome", "firefox"} {
			if hello == "socks5" && tc.name != "accepted" && tc.name != "rejected" && tc.name != "425" {
				continue
			}
			t.Run(tc.name+"/"+hello, func(t *testing.T) {
				var reject atomic.Bool
				var earlySent chan struct{}
				if tc.enabled && !tc.reject && tc.method != "POST" && tc.name != "get-body" {
					earlySent = make(chan struct{})
				}
				origin, observed := earlyDataServer(t, &reject, tc.tooEarly, earlySent)
				cache := &h3SessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), stored: make(chan struct{}, 4)}
				builder := surf.NewClient().Builder()
				if hello == "socks5" {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					require.NoError(t, err)
					t.Cleanup(func() { listener.Close() })
					proxy := socks5.NewServer()
					proxy.Context = t.Context()
					proxy.ProxyListenPacket = func(context.Context, string, string) (net.PacketConn, error) {
						return net.ListenPacket("udp4", "127.0.0.1:0")
					}
					go proxy.Serve(listener)
					builder.Proxy(g.String("socks5://" + listener.Addr().String()))
				}
				if hello == "datagram-padding" {
					builder.QUICSettings().InitialPaddingMode(quic.InitialPaddingDatagram).HandshakeAckBeforeData(true).Set()
					builder.HTTP3Settings().CoalesceInitialSettings(true).Set()
				}
				if hello == "coalesced" {
					builder.HTTP3Settings().CoalesceInitialSettings(true).Set()
				}
				if hello == "dedicated" {
					builder.QUICSettings().ConnectionIDLength(0).Set()
				}
				if hello == "chrome" {
					builder = builder.Impersonate().Chrome()
				}
				if hello == "firefox" {
					builder = builder.Impersonate().Firefox()
				}
				if earlySent != nil {
					var sent sync.Once
					builder.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
						return &earlyTrace{streams: make(map[quic.StreamID]bool), onEarly: func() { sent.Do(func() { close(earlySent) }) }}
					}).Set()
				}
				client := builder.ForceHTTP3().HTTP3Settings().EarlyData(tc.enabled).Set().TLSConfig(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}).Timeout(5 * time.Second).Build().Unwrap()
				t.Cleanup(func() { client.Close() })
				response := client.Get(g.String(origin)).Do()
				require.False(t, response.IsErr(), "%v", response.Err())
				response.Ok().Body.String().Unwrap()
				first := <-observed
				require.False(t, first.early)
				require.False(t, first.resumed)
				select {
				case <-cache.stored:
				case <-time.After(5 * time.Second):
					t.Fatal("no ticket")
				}
				client.GetClient().CloseIdleConnections()
				reject.Store(tc.reject)
				req := client.Get(g.String(origin))
				req.GetRequest().Method = tc.method
				if tc.name == "get-body" {
					req.Body("payload")
				}
				original := req.GetRequest()
				result := req.Do()
				require.False(t, result.IsErr(), "%v", result.Err())
				if body := result.Ok().GetResponse().Body; body != nil {
					_, err := io.Copy(io.Discard, body)
					require.NoError(t, err)
					body.Close()
				}
				require.Equal(t, tc.method, original.Method)
				got := <-observed
				require.Equal(t, tc.method, got.method)
				if tc.enabled && !tc.reject && tc.method != "POST" && tc.name != "get-body" {
					require.True(t, got.early, fmt.Sprint(got))
				} else {
					require.False(t, got.early)
				}
				require.True(t, got.resumed)
				if tc.tooEarly {
					retry := <-observed
					require.Equal(t, "GET", retry.method)
					require.False(t, retry.early, "425 retry must use 1-RTT")
					require.Equal(t, 425, result.Ok().GetResponse().StatusCode)
				}
			})
		}
	}
}

func TestHTTP3EarlyDataCustomHelloBuilds(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox", "custom"} {
		t.Run(browser, func(t *testing.T) {
			b := surf.NewClient().Builder()
			switch browser {
			case "chrome":
				b = b.Impersonate().Chrome()
			case "firefox":
				b = b.Impersonate().Firefox()
			case "custom":
				spec := h3QUICClientHello(t)
				b.HTTP3Settings().ClientHelloSpec(&spec)
			}
			result := b.ForceHTTP3().HTTP3Settings().EarlyData(true).Set().Build()
			require.False(t, result.IsErr(), "%v", result.Err())
			if result.IsOk() {
				result.Ok().Close()
			}
		})
	}
}

func TestHTTP3EarlyDataProtocolFallbackPreservesRequest(t *testing.T) {
	received := make(chan string, 2)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Method
		require.Empty(t, r.Header.Get("Alt-Used"))
		io.WriteString(w, "ok")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	b := surf.NewClient().Builder().ForceHTTP3()
	b.QUICSettings().HandshakeIdleTimeout(50 * time.Millisecond).Set()
	client := b.HTTP3Settings().EarlyData(true).AltUsed(true).Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(3 * time.Second).Build().Unwrap()
	defer client.Close()
	request := client.Get(g.String(origin.URL)).SetHeaders("X-Marker", "unchanged")
	original := request.GetRequest()
	before := original.Header.Clone()
	response, err := client.GetClient().Transport.RoundTrip(original)
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "ok", string(body))
	require.Equal(t, 2, response.ProtoMajor)

	require.Equal(t, "GET", <-received)
	require.Equal(t, "GET", original.Method)
	require.Equal(t, before, original.Header)
}

func TestHTTP3EarlyDataCanceledRequest(t *testing.T) {
	var reject atomic.Bool
	origin, observations := earlyDataServer(t, &reject, false, nil)
	client := surf.NewClient().Builder().ForceHTTP3().HTTP3Settings().EarlyData(true).Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(time.Second).Build().Unwrap()
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var ready atomic.Bool
	result := client.Get(g.String(origin)).HTTP3PriorityUpdates(func(*surf.HTTP3PriorityUpdater) { ready.Store(true) }).WithContext(ctx).Do()
	require.ErrorIs(t, result.Err(), context.Canceled)
	require.False(t, ready.Load())
	select {
	case got := <-observations:
		t.Fatalf("canceled request reached server: %+v", got)
	default:
	}
}
