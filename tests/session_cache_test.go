package surf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/surf"
	"github.com/enetx/surf/pkg/tlscache"
	"github.com/stretchr/testify/require"
)

// After the first request the server deliberately stops issuing or accepting
// tickets. A browser queue must offer its first ticket once, then send a cold
// ClientHello rather than repeatedly reusing that rejected identity.
func TestBrowserTCPTicketConsumptionOnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			var stopTickets atomic.Bool
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
				if !stopTickets.Load() {
					return nil, nil
				}
				clone := server.TLS.Clone()
				clone.GetConfigForClient = nil
				clone.SessionTicketsDisabled = true
				return clone, nil
			}
			server.StartTLS()
			defer server.Close()
			hellos := make(chan recordedClientHello, 4)
			builder := surf.NewClient().Builder().Proxy("").TLSConfig(&tls.Config{InsecureSkipVerify: true}).Session().ForceHTTP1().Timeout(10 * time.Second)
			if browser == "chrome" {
				builder.Impersonate().Chrome()
			} else {
				builder.Impersonate().Firefox()
			}
			builder.With(func(c *surf.Client) error {
				transport := c.GetTransport().(*http.Transport)
				dial := transport.DialContext
				transport.DialContext = func(ctx context.Context, network, address string) (netConn net.Conn, err error) {
					conn, err := dial(ctx, network, address)
					if err != nil {
						return nil, err
					}
					return &clientHelloConn{Conn: conn, hellos: hellos}, nil
				}
				return nil
			})
			client := builder.Build().Unwrap()
			defer client.Close()
			for attempt := 0; attempt < 3; attempt++ {
				response := client.Get(g.String(server.URL)).Do().Unwrap()
				response.Body.String().Unwrap()
				client.CloseIdleConnections()
				select {
				case hello := <-hellos:
					require.Equal(t, attempt == 1, slices.Contains(hello.extensions, 41), "PSK offer for attempt %d", attempt+1)
				case <-time.After(5 * time.Second):
					t.Fatal("no wire ClientHello")
				}
				stopTickets.Store(true)
			}
		})
	}
}

func TestBrowserSessionTicketsDisabledAndCustomCacheOwnership(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(disabled), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
			defer server.Close()
			cache := &versionTestCache{stored: make(chan *tls.ClientSessionState, 8)}
			client := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP1().Proxy("").
				TLSConfig(&tls.Config{InsecureSkipVerify: true, SessionTicketsDisabled: disabled}).SessionCache().Custom(cache).Set().Timeout(10 * time.Second).Build().Unwrap()
			defer client.Close()
			for range 2 {
				client.Get(g.String(server.URL)).Do().Unwrap().Body.String().Unwrap()
				client.CloseIdleConnections()
			}
			cache.mu.Lock()
			defer cache.mu.Unlock()
			if disabled {
				require.Empty(t, cache.entries)
			} else {
				require.NotEmpty(t, cache.entries, "TCP must use the supplied cache")
				for key := range cache.entries {
					require.True(t, strings.HasPrefix(key, "tcp:"))
				}
			}
		})
	}
}

func TestQUICRejectedEarlyDataUpdatesPendingTicketQueue(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			var reject atomic.Bool
			origin, _ := earlyDataServer(t, &reject, false, nil)
			queue := tlscache.New().TicketsPerKey(2).ClearEarlyDataOnReject(true).Build().Unwrap()
			type sample struct {
				found, early bool
				identity     []byte
			}
			observed := make(chan sample, 4)
			key := "localhost"
			if browser == "firefox" {
				key = "quic:00000001:localhost"
			}
			builder := surf.NewClient().Builder().Proxy("").TLSConfig(&tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}).SessionCache().Custom(queue).Set().ForceHTTP3().Timeout(10 * time.Second)
			if browser == "chrome" {
				builder.Impersonate().Chrome()
			} else if browser == "firefox" {
				builder.Impersonate().Firefox()
			}
			builder.HTTP3Settings().EarlyData(true).Set().QUICSettings().ResumeVersion(false).ResumeRTT(0).OnEarlyDataRejected(func(*quic.Conn) {
				state, ok := queue.Peek(key)
				got := sample{found: ok}
				if ok {
					identity, metadata, _ := state.ResumptionState()
					got.identity = identity
					got.early = metadata.EarlyData
				}
				observed <- got
			}).Set()
			client := builder.Build().Unwrap()
			defer client.Close()
			client.Get(g.String(origin)).Do().Unwrap().Body.String().Unwrap()
			client.CloseIdleConnections()
			var original *tls.ClientSessionState
			require.Eventually(t, func() bool { original, _ = queue.Peek(key); return original != nil }, 5*time.Second, time.Millisecond)
			identity, state, err := original.ResumptionState()
			require.NoError(t, err)
			require.True(t, state.EarlyData)
			data, err := state.Bytes()
			require.NoError(t, err)
			clone, err := tls.ParseSessionState(data)
			require.NoError(t, err)
			fake, err := tls.NewResumptionState([]byte("deliberately invalid ticket identity"), clone)
			require.NoError(t, err)
			queue.Put(key, fake)
			client.Get(g.String(origin)).Do().Unwrap().Body.String().Unwrap()
			select {
			case got := <-observed:
				require.True(t, got.found)
				require.True(t, bytes.Equal(identity, got.identity))
				require.False(t, got.early, "remaining ticket must retain PSK but lose early-data permission")
			case <-time.After(5 * time.Second):
				t.Fatal("no genuine TLS 0-RTT rejection callback")
			}
		})
	}
}

func liveCacheTicket(t *testing.T) *tls.ClientSessionState {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	cache := &versionTestCache{stored: make(chan *tls.ClientSessionState, 4)}
	client := surf.NewClient().Builder().Proxy("").TLSConfig(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}).Build().Unwrap()
	defer client.Close()
	client.Get(g.String(server.URL)).Do().Unwrap().Body.String().Unwrap()
	select {
	case state := <-cache.stored:
		return state
	case <-time.After(5 * time.Second):
		t.Fatal("no real TLS client ticket")
		return nil
	}
}

// The nested builder must preserve browser defaults, apply overrides regardless
// of profile selection order, and surface validation through the parent's Build.
func TestSessionCacheNestedBuilderPolicies(t *testing.T) {
	seed := liveCacheTicket(t)
	for _, mode := range []string{"chrome-default", "firefox-default", "before-profile", "after-profile", "session-before-tls", "session-after-tls", "no-cookies", "repeated-set", "clock", "group"} {
		t.Run(mode, func(t *testing.T) {
			builder := surf.NewClient().Builder().Proxy("")
			expected := []string{"c", "b"}
			switch mode {
			case "chrome-default":
				builder.Impersonate().Chrome().Session()
			case "firefox-default":
				builder.Impersonate().Firefox().Session()
				expected = []string{"c", "b", "a"}
			case "before-profile":
				builder.SessionCache().TicketsPerKey(1).Set().Impersonate().Chrome()
				expected = []string{"c"}
			case "after-profile":
				builder.Impersonate().Chrome().SessionCache().TicketsPerKey(1).Set()
				expected = []string{"c"}
			case "session-before-tls":
				builder.Impersonate().Chrome().Session().TLSConfig(&tls.Config{})
			case "session-after-tls":
				builder.Impersonate().Chrome().TLSConfig(&tls.Config{}).Session()
			case "no-cookies":
				builder.SessionCache().Capacity(8).TicketsPerKey(2).Order(surf.SessionTicketEarliestExpiryFirst).
					ReuseTLS12(false).DiscardOnExpiry(false).ClearEarlyDataOnReject(true).Both().Set()
				expected = []string{"c", "a"}
			case "repeated-set":
				builder.SessionCache().TicketsPerKey(3).Set().SessionCache().TicketsPerKey(1).Set()
				expected = []string{"c"}
			case "clock":
				builder.SessionCache().Clock(func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }).Set()
				expected = nil
			case "group":
				builder.SessionCache().TicketsPerKey(3).Group(func(state *tls.ClientSessionState) string {
					identity, _, err := state.ResumptionState()
					require.NoError(t, err)
					return string(identity)
				}).Set()
				expected = []string{"c"}
			}
			client := builder.Build().Unwrap()
			defer client.Close()
			if mode == "no-cookies" {
				require.Nil(t, client.GetClient().Jar)
			}
			cache := client.GetTLSConfig().ClientSessionCache
			require.NotNil(t, cache)
			for _, label := range []string{"a", "b", "c"} {
				_, state, err := seed.ResumptionState()
				require.NoError(t, err)
				data, err := state.Bytes()
				require.NoError(t, err)
				cloned, err := tls.ParseSessionState(data)
				require.NoError(t, err)
				copy, err := tls.NewResumptionState([]byte(label), cloned)
				require.NoError(t, err)
				cache.Put("test-key", copy)
			}
			for _, label := range expected {
				state, ok := cache.Get("test-key")
				require.True(t, ok)
				identity, _, err := state.ResumptionState()
				require.NoError(t, err)
				require.Equal(t, label, string(identity))
			}
			_, ok := cache.Get("test-key")
			require.False(t, ok, "every retained TLS 1.3 ticket must be consumed once")
		})
	}
	for _, scope := range []string{"tcp", "quic"} {
		t.Run("invalid-"+scope, func(t *testing.T) {
			builder := surf.NewClient().Builder()
			cache := builder.SessionCache()
			if scope == "tcp" {
				cache.TCP()
			} else {
				cache.QUIC()
			}
			result := cache.Capacity(0).Set().Build()
			require.True(t, result.IsErr())
			require.Contains(t, result.Err().Error(), strings.ToUpper(scope)+" session cache")
		})
	}
}

func TestSessionCacheCustomOwnershipAndScopes(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		for _, scope := range []string{"both", "tcp", "quic", "disabled"} {
			t.Run(browser+"/"+scope, func(t *testing.T) {
				peer := newH3Peer(t)
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
				defer server.Close()
				tcp := &versionTestCache{stored: make(chan *tls.ClientSessionState, 8)}
				quic := &versionTestCache{stored: make(chan *tls.ClientSessionState, 8)}
				builder := surf.NewClient().Builder().Proxy("").TLSConfig(&tls.Config{InsecureSkipVerify: true}).Session().Timeout(10 * time.Second)
				if browser == "chrome" {
					builder.Impersonate().Chrome()
				}
				if browser == "firefox" {
					builder.Impersonate().Firefox()
				}
				cache := builder.SessionCache()
				switch scope {
				case "both":
					cache.Custom(tcp)
				case "tcp":
					cache.TCP().Custom(tcp)
				case "quic":
					cache.QUIC().Custom(quic)
				case "disabled":
					cache.Custom(nil)
				}
				cache.Set().ForceHTTP3().HTTP3Settings().ConnectionRacing(true).Set()
				client := builder.Build().Unwrap()
				defer client.Close()
				client.Get(g.String(server.URL)).Do().Unwrap().Body.String().Unwrap()
				peer.request(t, client)
				// Response data, TLS tickets and server SETTINGS use independent
				// QUIC streams. HTTP/3 publishes a ticket only with its SETTINGS;
				// the completed response does not order this cache callback.
				if scope == "both" || scope == "quic" {
					require.Eventually(t, func() bool {
						if scope == "both" {
							tcp.mu.Lock()
							defer tcp.mu.Unlock()
							return len(tcp.entries) >= 2
						}
						quic.mu.Lock()
						defer quic.mu.Unlock()
						return len(quic.entries) == 1
					}, 5*time.Second, time.Millisecond)
				}
				tcp.mu.Lock()
				tcpCount := len(tcp.entries)
				tcp.mu.Unlock()
				quic.mu.Lock()
				quicCount := len(quic.entries)
				quic.mu.Unlock()
				switch scope {
				case "both":
					require.GreaterOrEqual(t, tcpCount, 2, "the shared application cache receives both protocols")
				case "tcp":
					require.Equal(t, 1, tcpCount)
					require.Zero(t, quicCount)
				case "quic":
					require.Zero(t, tcpCount)
					require.Equal(t, 1, quicCount)
				case "disabled":
					require.Nil(t, client.GetTLSConfig().ClientSessionCache)
				}
			})
		}
	}
}

func TestSessionKeepsExplicitTLSCache(t *testing.T) {
	seed := liveCacheTicket(t)
	for _, before := range []bool{false, true} {
		t.Run(strconv.FormatBool(before), func(t *testing.T) {
			cache := &versionTestCache{}
			builder := surf.NewClient().Builder().Impersonate().Chrome()
			config := &tls.Config{ClientSessionCache: cache}
			if before {
				builder.TLSConfig(config).Session()
			} else {
				builder.Session().TLSConfig(config)
			}
			client := builder.Build().Unwrap()
			defer client.Close()
			require.Same(t, config, client.GetTLSConfig())
			client.GetTLSConfig().ClientSessionCache.Put("ownership", seed)
			stored, ok := cache.Get("tcp:ownership")
			require.True(t, ok)
			require.Same(t, seed, stored)
			require.NotNil(t, client.GetClient().Jar)
		})
	}
}

func TestSessionCacheRetainsNativeTLSConfig(t *testing.T) {
	config := &tls.Config{}
	client := surf.NewClient().Builder().TLSConfig(config).SessionCache().Set().Build().Unwrap()
	defer client.Close()
	require.Same(t, config, client.GetTLSConfig())
	require.Same(t, config, client.GetTransport().(*http.Transport).TLSClientConfig)
}
