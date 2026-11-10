package surf_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
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
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

// The same origin changes SETTINGS only on a new connection, as RFC 9114
// requires. Every connection gets a fresh decoder and a graceful GOAWAY.
func qpackReconnectServer(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	config := cert.TLS.Clone()
	cert.Close()
	config.NextProtos = []string{"h3"}
	listener, err := quic.ListenAddr("127.0.0.1:0", config, nil)
	require.NoError(t, err)
	closed := make(chan struct{}, 4)
	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	var connections []*quic.Conn
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		listener.Close()
		mu.Lock()
		for _, c := range connections {
			c.CloseWithError(0, "")
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Go(func() {
		for n := 0; ; n++ {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			capacity := []uint64{4096, 0, 65536}[n%3]
			settings := g.NewMapOrd[uint64, uint64]()
			settings.Insert(1, capacity)
			settings.Insert(7, 4)
			server := &http3.Server{AdditionalSettings: settings}
			id := n
			var once sync.Once
			server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/cancel" {
					<-r.Context().Done()
					return
				}
				w.Header().Set("X-Connection", fmt.Sprint(id))
				if r.URL.Path == "/goaway" {
					once.Do(func() {
						wg.Go(func() {
							defer func() { closed <- struct{}{} }()
							shutdownCtx, stop := context.WithTimeout(ctx, 5*time.Second)
							defer stop()
							if err := server.Shutdown(shutdownCtx); err != nil && ctx.Err() == nil {
								t.Errorf("shutdown: %v", err)
							}
						})
					})
				}
				io.WriteString(w, r.Header.Get("X-Value"))
			})
			wg.Go(func() {
				if err := server.ServeQUICConn(conn); err != nil && ctx.Err() == nil && !strings.Contains(err.Error(), "NO_ERROR") {
					t.Logf("connection drained: %v", err)
				}
			})
		}
	})
	return "https://" + listener.Addr().String(), closed
}

func TestHTTP3QPACKReconnectSettingsGOAWAYAndCancel(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			origin, drained := qpackReconnectServer(t)
			builder := surf.NewClient().Builder()
			if browser == "chrome" {
				builder = builder.Impersonate().Chrome()
			} else {
				builder = builder.Impersonate().Firefox()
			}
			var insertions atomic.Int64
			client := builder.ForceHTTP3().HTTP3Settings().QpackIndexingPolicy(func(string, string) bool { insertions.Add(1); return true }).Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			for connection := range 3 {
				before := insertions.Load()
				for n := range 8 {
					value := fmt.Sprintf("value-%d-%d", connection, n%2)
					response := client.Get(g.String(origin+"/repeat")).SetHeaders("X-Value", value).Do()
					require.False(t, response.IsErr(), "%v", response.Err())
					require.Equal(t, g.String(value), response.Ok().Body.String().Unwrap())
					require.Equal(t, fmt.Sprint(connection), response.Ok().GetResponse().Header.Get("X-Connection"))
				}
				if connection == 1 {
					require.Equal(t, before, insertions.Load(), "zero-capacity peer must not insert")
				} else {
					require.Greater(t, insertions.Load(), before, "new peer SETTINGS must enable a fresh dynamic table")
				}
				ctx, cancel := context.WithCancel(t.Context())
				ready := make(chan struct{})
				done := make(chan error, 1)
				go func() {
					result := client.Get(g.String(origin + "/cancel")).WithContext(ctx).HTTP3PriorityUpdates(func(*surf.HTTP3PriorityUpdater) { close(ready) }).Do()
					done <- result.Err()
				}()
				select {
				case <-ready:
				case <-time.After(5 * time.Second):
					t.Fatal("request not ready")
				}
				cancel()
				require.ErrorIs(t, <-done, context.Canceled)
				result := client.Get(g.String(origin+"/goaway")).SetHeaders("X-Value", "drain").Do()
				require.False(t, result.IsErr(), "%v", result.Err())
				require.Equal(t, g.String("drain"), result.Ok().Body.String().Unwrap())
				select {
				case <-drained:
				case <-time.After(6 * time.Second):
					t.Fatal("GOAWAY did not drain connection")
				}
			}
		})
	}
}
