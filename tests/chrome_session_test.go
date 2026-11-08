package surf_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/enetx/surf/tests/internal/wiretest"
)

func TestChromeSessionResumption(t *testing.T) {
	t.Parallel()

	for _, platform := range []string{"desktop", "android", "ios"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			for _, protocol := range []string{"http/1.1", "h2"} {
				for _, session := range []bool{false, true} {
					name := fmt.Sprintf("%s/%s/%s/session=%t", platform, tls.VersionName(version), protocol, session)
					t.Run(name, func(t *testing.T) {
						testChromeSessionResumption(t, platform, version, protocol, session)
					})
				}
			}
		}
	}
}

func testChromeSessionResumption(t *testing.T, platform string, version uint16, protocol string, session bool) {
	t.Helper()

	var resumed atomic.Int32
	var requests atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.NegotiatedProtocol != protocol {
			t.Errorf("negotiated protocol = %q, want %q", r.TLS.NegotiatedProtocol, protocol)
		}
		if r.TLS.DidResume {
			resumed.Add(1)
		}
		if requests.Add(1) > 1 {
			cookie, err := r.Cookie("session")
			if session && (err != nil || cookie.Value != "chrome") {
				t.Error("session cookie was not preserved across connections")
			} else if !session && err == nil {
				t.Error("cookie persisted without Session")
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "chrome", Path: "/", Secure: true})
		w.Write([]byte("ok"))
	}))
	ts.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
	ts.EnableHTTP2 = protocol == "h2"
	ts.StartTLS()
	defer ts.Close()

	hellos := make(chan recordedClientHello, 4)
	builder := surf.NewClient().Builder().With(func(c *surf.Client) error {
		transport := c.GetTransport().(*http.Transport)
		dial := transport.DialContext
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &clientHelloConn{Conn: conn, hellos: hellos}, nil
		}
		return nil
	}).Timeout(5 * time.Second)
	if session {
		builder.Session()
	}
	im := builder.Impersonate()
	switch platform {
	case "android":
		im.Android()
	case "ios":
		im.IOS()
	}
	im.Chrome()
	if protocol == "http/1.1" {
		builder.ForceHTTP1()
	}
	client := builder.Build().Unwrap()
	defer client.Close()
	for attempt := range 3 {
		resp := client.Get(g.String(ts.URL)).Do()
		if resp.IsErr() {
			t.Fatal(resp.Err())
		}
		if body := resp.Ok().Body.String(); body.IsErr() || body.Ok() != "ok" {
			t.Fatalf("unexpected response body: %v", body)
		}
		client.CloseIdleConnections()

		select {
		case hello := <-hellos:
			wantPSK := session && platform != "ios" && version == tls.VersionTLS13 && attempt > 0
			if got := slices.Contains(hello.extensions, 41); got != wantPSK {
				t.Errorf("connection %d PSK present = %t, want %t", attempt+1, got, wantPSK)
			}
			if wantPSK && hello.extensions[len(hello.extensions)-1] != 41 {
				t.Error("PSK must remain the last extension")
			}
			if got := slices.Contains(hello.extensions, 35); got != (platform != "ios") {
				t.Errorf("connection %d session_ticket present = %t", attempt+1, got)
			}
			_, details := wiretest.ClientHello(t, hello.raw, false)
			if platform != "ios" && (!slices.Contains([]int{144, 176, 208, 240}, details.ECHPayloadLength) || details.ECHAEAD != 1) {
				t.Errorf("unexpected Chrome GREASE ECH: payload=%d AEAD=%d", details.ECHPayloadLength, details.ECHAEAD)
			}
		default:
			t.Fatal("ClientHello was not recorded")
		}
	}
	wantResumed := int32(0)
	if session && platform != "ios" {
		wantResumed = 2
	}
	if got := resumed.Load(); got != wantResumed {
		t.Errorf("resumed handshakes = %d, want %d", got, wantResumed)
	}
}
