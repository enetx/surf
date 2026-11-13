package surf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserALPNFailures(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, mode := range []string{"certificate", "unsupported-alpn", "canceled"} {
			t.Run(browser+"/"+mode, func(t *testing.T) {
				var handshakes, requests atomic.Int32
				ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1) }))
				protocols := []string{"http/1.1"}
				if mode == "unsupported-alpn" {
					protocols = []string{"not-http"}
				}
				ts.TLS = &tls.Config{NextProtos: protocols, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { handshakes.Add(1); return nil, nil }}
				ts.StartTLS()
				defer ts.Close()
				roots := x509.NewCertPool()
				if mode != "certificate" {
					roots.AddCert(ts.Certificate())
				}
				b := surf.NewClient().Builder().Proxy("").TLSConfig(&tls.Config{RootCAs: roots}).Timeout(time.Second)
				if browser == "chrome" {
					b.JA().Chrome158()
				} else {
					b.JA().Firefox160()
				}
				c := b.Build().Unwrap()
				defer c.Close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if mode == "canceled" {
					cancel()
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := c.GetClient().Do(req)
				if resp != nil {
					resp.Body.Close()
				}
				if err == nil {
					t.Fatal("failure must not turn into a request")
				}
				expected := int32(1)
				if mode == "canceled" {
					expected = 0
				}
				if handshakes.Load() != expected || requests.Load() != 0 {
					t.Errorf("handshakes=%d requests=%d", handshakes.Load(), requests.Load())
				}
			})
		}
	}
}
