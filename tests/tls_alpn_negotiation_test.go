package surf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestBrowserALPNNegotiation(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, mode := range []string{"explicit-h1", "no-alpn", "keepalive", "stream-post", "preconnect"} {
			t.Run(browser+"/"+mode, func(t *testing.T) {
				var handshakes, received atomic.Int32
				ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					received.Add(1)
					data, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, err.Error(), 500)
						return
					}
					fmt.Fprintf(w, "%s:%s", r.Method, data)
				}))
				protos := []string{"http/1.1"}
				if mode == "no-alpn" {
					protos = []string{}
				}
				ts.TLS = &tls.Config{NextProtos: protos, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { handshakes.Add(1); return nil, nil }}
				ts.StartTLS()
				defer ts.Close()
				roots := x509.NewCertPool()
				roots.AddCert(ts.Certificate())
				b := surf.NewClient().Builder().Proxy("").TLSConfig(&tls.Config{RootCAs: roots}).Timeout(5 * time.Second)
				if browser == "chrome" {
					b.JA().Chrome158()
				} else {
					b.JA().Firefox160()
				}
				c := b.Build().Unwrap()
				defer c.Close()
				rounds := 1
				if mode == "keepalive" {
					rounds = 3
				}
				for range rounds {
					method := http.MethodGet
					var body io.Reader
					if mode == "stream-post" {
						method = http.MethodPost
						body = io.NopCloser(strings.NewReader("one-shot-payload"))
					}
					req, err := http.NewRequestWithContext(context.Background(), method, ts.URL, body)
					if err != nil {
						t.Fatal(err)
					}
					if mode == "stream-post" && req.GetBody != nil {
						t.Fatal("fixture body must not be rewindable")
					}
					if mode == "preconnect" {
						p, ok := c.GetClient().Transport.(interface{ Preconnect(*http.Request) error })
						if !ok {
							t.Fatalf("missing existing Preconnect: %T", c.GetClient().Transport)
						}
						if err = p.Preconnect(req); err != nil {
							t.Fatal(err)
						}
					}
					resp, err := c.GetClient().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					data, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					expected := method + ":"
					if body != nil {
						expected += "one-shot-payload"
					}
					if string(data) != expected {
						t.Errorf("body=%q want %q", data, expected)
					}
					if mode == "no-alpn" && resp.TLS.NegotiatedProtocol != "" {
						t.Errorf("fixture negotiated %q instead of omitting ALPN", resp.TLS.NegotiatedProtocol)
					}
					if resp.ProtoMajor != 1 {
						t.Errorf("protocol=%v", resp.Proto)
					}
				}
				t.Logf("handshakes=%d requests=%d", handshakes.Load(), received.Load())
				if n := handshakes.Load(); n != 1 {
					t.Errorf("same eligible HTTP/1 connection needs one handshake, got %d", n)
				}
			})
		}
	}
}
