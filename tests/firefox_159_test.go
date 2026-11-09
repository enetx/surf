package surf_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/enetx/surf/tests/internal/wiretest"
)

func TestFirefox159JAEntryPoints(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		configure func(*surf.Builder) *surf.Builder
	}{
		{"current", func(b *surf.Builder) *surf.Builder { return b.JA().Firefox() }},
		{"versioned", func(b *surf.Builder) *surf.Builder { return b.JA().Firefox159() }},
		{"impersonate", func(b *surf.Builder) *surf.Builder { return b.Impersonate().Firefox() }},
	}
	// The local IP endpoint omits SNI; all other extensions retain capture order.
	want := []uint16{23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newHelloRecorder(t)
			for _, hello := range r.collect(t, 3, tc.configure) {
				if !slices.Equal(hello, want) {
					t.Errorf("Firefox 159 extension order\n got: %v\nwant: %v", hello, want)
				}
			}
		})
	}
}

func TestFirefox159SessionResumption(t *testing.T) {
	t.Parallel()

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			for _, protocol := range []string{"http/1.1", "h2"} {
				t.Run(protocol, func(t *testing.T) {
					testFirefox159SessionResumption(t, version, protocol)
				})
			}
		})
	}
}

func testFirefox159SessionResumption(t *testing.T, version uint16, protocol string) {
	t.Helper()

	var resumed atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.NegotiatedProtocol != protocol {
			t.Errorf("negotiated protocol = %q, want %q", r.TLS.NegotiatedProtocol, protocol)
		}
		if r.TLS.DidResume {
			resumed.Add(1)
		}
		w.Write([]byte("ok"))
	}))
	// Match the captured server's 113-byte ticket so ECH sizing is comparable
	// to the real browser's fresh (240) and resumed (400) payload lengths.
	var sessions sync.Map
	ts.TLS = &tls.Config{
		MinVersion: version,
		MaxVersion: version,
		WrapSession: func(_ tls.ConnectionState, state *tls.SessionState) ([]byte, error) {
			ticket := make([]byte, 113)
			if _, err := rand.Read(ticket); err != nil {
				return nil, err
			}
			sessions.Store(string(ticket), state)
			return ticket, nil
		},
		UnwrapSession: func(ticket []byte, _ tls.ConnectionState) (*tls.SessionState, error) {
			if state, ok := sessions.Load(string(ticket)); ok {
				return state.(*tls.SessionState), nil
			}
			return nil, nil
		},
	}
	ts.EnableHTTP2 = protocol == "h2"
	ts.StartTLS()
	defer ts.Close()

	hellos := make(chan recordedClientHello, 4)
	builder := surf.NewClient().Builder().With(func(c *surf.Client) error {
		transport := c.GetTransport().(*http.Transport)
		dial := transport.DialContext
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Keep the captured SNI while sending every connection locally.
			conn, err := dial(ctx, network, ts.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			return &clientHelloConn{Conn: conn, hellos: hellos}, nil
		}
		return nil
	}).Session().Impersonate().Firefox().Timeout(5 * time.Second)
	if protocol == "http/1.1" {
		builder.ForceHTTP1()
	}
	client := builder.Build().Unwrap()
	defer client.Close()
	for attempt := range 3 {
		resp := client.Get("https://tls.peet.ws/api/all").Do()
		if resp.IsErr() {
			t.Fatal(resp.Err())
		}
		if body := resp.Ok().Body.String(); body.IsErr() || body.Ok() != "ok" {
			t.Fatalf("unexpected response body: %v", body)
		}
		client.CloseIdleConnections()

		select {
		case hello := <-hellos:
			want := []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037}
			wantPayload := 240
			if version == tls.VersionTLS13 && attempt > 0 {
				// Firefox replaces the TLS 1.2 ticket extension with a final PSK.
				want = append(slices.Delete(want, 5, 6), 41)
				wantPayload = 400
			}
			if !slices.Equal(hello.extensions, want) {
				t.Errorf("connection %d extension order\n got: %v\nwant: %v", attempt+1, hello.extensions, want)
			}
			_, details := wiretest.ClientHello(t, hello.raw, false)
			if details.ECHPayloadLength != wantPayload {
				t.Errorf("connection %d ECH payload = %d, want %d", attempt+1, details.ECHPayloadLength, wantPayload)
			}
		default:
			t.Fatal("ClientHello was not recorded")
		}
	}
	if got := resumed.Load(); got != 2 {
		t.Errorf("resumed handshakes = %d, want 2", got)
	}
}
