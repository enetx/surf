package surf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/http/httptrace"
	"github.com/enetx/surf"
)

func TestBrowserParallelALPN(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) { testBrowserParallelALPN(t, browser) })
	}
}

func testBrowserParallelALPN(t *testing.T, browser string) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var calls, hellos, withoutH2, handlers atomic.Int32
	bothDialing := make(chan struct{})
	bothHandling := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handlers.Add(1) == 2 {
			close(bothHandling)
		}
		select {
		case <-bothHandling:
		case <-ctx.Done():
			return
		}
		io.WriteString(w, r.URL.Path)
	}))
	ts.TLS = &tls.Config{NextProtos: []string{"http/1.1"}, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		hellos.Add(1)
		hasH2 := false
		for _, p := range h.SupportedProtos {
			if p == "h2" {
				hasH2 = true
			}
		}
		if !hasH2 {
			withoutH2.Add(1)
		}
		select {
		case <-bothDialing:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return nil, nil
	}}
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	builder := surf.NewClient().Builder().Proxy("").TLSConfig(&tls.Config{RootCAs: roots}).Timeout(5 * time.Second)
	if browser == "chrome" {
		builder.JA().Chrome158()
	} else {
		builder.JA().Firefox160()
	}
	client := builder.Build().Unwrap()
	defer client.Close()
	trace := &httptrace.ClientTrace{GetConn: func(string) {
		if calls.Add(1) == 2 {
			close(bothDialing)
		}
	}}
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for i := range 2 {
		wg.Go(func() {
			req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, fmt.Sprintf("%s/%d", ts.URL, i), nil)
			if err != nil {
				errors <- err
				return
			}
			resp, err := client.GetClient().Do(req)
			if err != nil {
				errors <- err
				return
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err == nil && string(data) != fmt.Sprintf("/%d", i) {
				err = fmt.Errorf("wrong response %q", data)
			}
			errors <- err
		})
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("handshakes=%d without_h2=%d", hellos.Load(), withoutH2.Load())
	if n := withoutH2.Load(); n != 0 {
		t.Errorf("ALPN selection must not remove h2 from later ClientHellos: %d", n)
	}
}
