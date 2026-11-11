package surf_test

import (
	"context"
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

// The server gate makes early readiness observable independently of scheduler
// speed. It holds the resumed ServerHello until after the client's 0-RTT send.
func newEarlyRacingPeer(t *testing.T, gate <-chan struct{}, cold bool) (*racingPeer, *earlyTrace) {
	t.Helper()
	trace := &earlyTrace{streams: make(map[quic.StreamID]bool)}
	var handshakes atomic.Int32
	p := newRacingPeer(t, true, true, true, func(p *racingPeer) {
		p.quic.QUICConfig = &quic.Config{Allow0RTT: true, Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }}
		p.quic.TLSConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			if handshakes.Add(1) == 1 && !cold {
				return nil, nil
			}
			select {
			case <-gate:
				return nil, nil
			case <-info.Context().Done():
				return nil, info.Context().Err()
			}
		}
	})
	return p, trace
}

func earlyRacingClient(t *testing.T, browser string, sent chan struct{}) (*surf.Client, *h3SessionCache) {
	t.Helper()
	cache := &h3SessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(8), stored: make(chan struct{}, 8)}
	b := racingBuilder(browser)
	if sent != nil {
		var once sync.Once
		b.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &earlyTrace{streams: make(map[quic.StreamID]bool), onEarly: func() { once.Do(func() { close(sent) }) }}
		}).Set()
	}
	client := b.HTTP3Settings().ConnectionRacing(true).TCPFallbackDelay(40 * time.Millisecond).EarlyData(true).Set().
		TLSConfig(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}).Timeout(10 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	return client, cache
}

func warmEarlyRacing(t *testing.T, client *surf.Client, cache *h3SessionCache, origin string) {
	t.Helper()
	response := client.Get(g.String(origin)).Do().Unwrap()
	require.Equal(t, "HTTP/3.0", response.Proto.Std())
	response.Body.String().Unwrap()
	select {
	case <-cache.stored:
	case <-time.After(5 * time.Second):
		t.Fatal("no session ticket for the resumed race")
	}
	client.CloseIdleConnections()
}

func TestHTTP3EarlyDataConnectionRacingBrowserPolicies(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			gate := make(chan struct{})
			var release sync.Once
			defer release.Do(func() { close(gate) })
			p, trace := newEarlyRacingPeer(t, gate, false)
			sent := make(chan struct{})
			client, cache := earlyRacingClient(t, browser, sent)
			warmEarlyRacing(t, client, cache, p.url)
			result := make(chan g.Result[*surf.Response], 1)
			go func() { result <- client.Get(g.String(p.url)).Do() }()
			select {
			case <-sent:
			case <-time.After(5 * time.Second):
				t.Fatal("race waited for the handshake instead of sending eligible 0-RTT")
			}
			close(p.tcpGate)
			if browser == "firefox" {
				// TCP wins while the QUIC ServerHello is still held back.
				select {
				case r := <-result:
					require.False(t, r.IsErr(), "%v", r.Err())
					require.Equal(t, "HTTP/2.0", r.Ok().Proto.Std())
					r.Ok().Body.String().Unwrap()
				case <-time.After(5 * time.Second):
					t.Fatal("Firefox's TCP backup stopped at early readiness")
				}
				require.EqualValues(t, 1, p.tcpCalls.Load())
				release.Do(func() { close(gate) })
			} else {
				// Chrome has committed to early-ready QUIC; TCP owns no request.
				release.Do(func() { close(gate) })
				r := <-result
				require.False(t, r.IsErr(), "%v", r.Err())
				require.Equal(t, "HTTP/3.0", r.Ok().Proto.Std())
				r.Ok().Body.String().Unwrap()
				require.Zero(t, p.tcpCalls.Load())
				require.EqualValues(t, 2, p.quicCalls.Load())
				require.True(t, trace.used(0))
			}
		})
	}
}

func TestHTTP3EarlyDataColdRaceDoesNotSendLosingRequest(t *testing.T) {
	gate := make(chan struct{})
	defer close(gate)
	p, _ := newEarlyRacingPeer(t, gate, true)
	client, _ := earlyRacingClient(t, "firefox", nil)
	close(p.tcpGate)
	r := client.Get(g.String(p.url)).Do().Unwrap()
	require.Equal(t, "HTTP/2.0", r.Proto.Std())
	r.Body.String().Unwrap()
	require.EqualValues(t, 1, p.tcpCalls.Load())
	require.Zero(t, p.quicCalls.Load())
}

func TestHTTP3EarlyDataUnsafeRequestKeepsConfirmedRace(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			gate := make(chan struct{})
			defer close(gate)
			p, trace := newEarlyRacingPeer(t, gate, false)
			sent := make(chan struct{})
			client, cache := earlyRacingClient(t, browser, sent)
			warmEarlyRacing(t, client, cache, p.url)
			close(p.tcpGate)
			r := client.Post(g.String(p.url)).Body("post-body").Do().Unwrap()
			require.Equal(t, "HTTP/2.0", r.Proto.Std())
			r.Body.String().Unwrap()
			require.False(t, trace.used(0))
			require.EqualValues(t, 1, p.quicCalls.Load(), "POST must not use speculative HTTP/3")
			require.EqualValues(t, 1, p.tcpCalls.Load())
			select {
			case <-sent:
				t.Fatal("POST was emitted in 0-RTT")
			default:
			}
		})
	}
}

func TestHTTP3EarlyDataRacingCancellation(t *testing.T) {
	gate := make(chan struct{})
	defer close(gate)
	p, _ := newEarlyRacingPeer(t, gate, false)
	sent := make(chan struct{})
	client, cache := earlyRacingClient(t, "firefox", sent)
	warmEarlyRacing(t, client, cache, p.url)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Get(g.String(p.url)).WithContext(ctx).Do().Err() }()
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("no early request before cancellation")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("canceling a speculative request did not release its caller")
	}
	close(p.tcpGate)
	require.Zero(t, p.tcpCalls.Load())
}
