package surf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"golang.org/x/net/http2/hpack"
)

func TestRoundTripperHTTP1FallbackOnServerErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		reset        bool
		code         http2.ErrCode
		lastStreamID uint32
		debugData    string
		keepOpen     bool
		fallback     bool
		firefox      bool
	}{
		{name: "rst_http11_required", reset: true, code: http2.ErrCodeHTTP11Required, fallback: true},
		{name: "rst_internal_error", reset: true, code: http2.ErrCodeInternal},
		{name: "rst_cancel", reset: true, code: http2.ErrCodeCancel},
		{name: "goaway_http11_required_unprocessed", code: http2.ErrCodeHTTP11Required, lastStreamID: 0, fallback: true},
		{name: "goaway_http11_required_open_connection", code: http2.ErrCodeHTTP11Required, lastStreamID: 0, keepOpen: true, fallback: true},
		{name: "goaway_http11_required_processed", code: http2.ErrCodeHTTP11Required, lastStreamID: 1, fallback: true},
		{name: "goaway_internal_unprocessed", code: http2.ErrCodeInternal, lastStreamID: 0},
		{name: "goaway_internal_processed", code: http2.ErrCodeInternal, lastStreamID: 1},
		{name: "goaway_debug_mentions_http11_required", code: http2.ErrCodeInternal, lastStreamID: 1, debugData: "HTTP_1_1_REQUIRED"},
		{name: "goaway_protocol_unprocessed", code: http2.ErrCodeProtocol, lastStreamID: 0},
		{name: "goaway_protocol_processed", code: http2.ErrCodeProtocol, lastStreamID: 1},
		{name: "goaway_no_error_processed", code: http2.ErrCodeNo, lastStreamID: 1},
		{name: "firefox_rst_http11_required", reset: true, code: http2.ErrCodeHTTP11Required, fallback: true, firefox: true},
		{name: "firefox_goaway_http11_required", code: http2.ErrCodeHTTP11Required, fallback: true, firefox: true},
	}
	for _, tc := range cases {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				t.Parallel()
				var h1Requests, h2Requests atomic.Int32
				release := make(chan struct{})
				ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if tc.firefox && (r.Header.Get("TE") != "" || r.Header.Get("Connection") != "keep-alive") {
						t.Errorf("Firefox fallback headers: TE=%q Connection=%q", r.Header.Get("TE"), r.Header.Get("Connection"))
					}
					h1Requests.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Errorf("read fallback body: %v", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					_, _ = io.WriteString(w, r.Method+"\n"+string(body))
				}))
				ts.EnableHTTP2 = true
				ts.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
					"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
						preface := make([]byte, len(http2.ClientPreface))
						if _, err := io.ReadFull(conn, preface); err != nil {
							return
						}
						fr := http2.NewFramer(conn, conn)
						if err := fr.WriteSettings(); err != nil {
							return
						}
						var streamID uint32
						for {
							frame, err := fr.ReadFrame()
							if err != nil {
								return
							}
							ended := false
							switch f := frame.(type) {
							case *http2.SettingsFrame:
								if !f.IsAck() {
									if err := fr.WriteSettingsAck(); err != nil {
										return
									}
								}
							case *http2.HeadersFrame:
								if tc.firefox {
									fields, err := hpack.NewDecoder(4096, nil).DecodeFull(f.HeaderBlockFragment())
									if err != nil {
										t.Error(err)
									}
									var te string
									for _, field := range fields {
										if field.Name == "te" {
											te = field.Value
										}
										if field.Name == "connection" {
											t.Error("HTTP/1 default leaked into HTTP/2")
										}
									}
									if te != "trailers" {
										t.Errorf("Firefox HTTP/2 TE=%q, want trailers", te)
									}
								}
								h2Requests.Add(1)
								streamID = f.StreamID
								ended = f.StreamEnded()
							case *http2.DataFrame:
								ended = f.StreamID == streamID && f.StreamEnded()
							}
							// Consume POST data before rejecting the stream, so fallback must
							// restore the body rather than reuse an unread request body.
							if !ended {
								continue
							}
							if tc.reset {
								_ = fr.WriteRSTStream(streamID, tc.code)
							} else {
								_ = fr.WriteGoAway(tc.lastStreamID, tc.code, []byte(tc.debugData))
							}
							if tc.keepOpen {
								<-release
							}
							return
						}
					},
				}
				ts.StartTLS()
				defer ts.Close()
				defer close(release)
				builder := surf.NewClient().Builder().Timeout(5 * time.Second)
				if tc.firefox {
					builder.Impersonate().Windows().Firefox()
				} else {
					builder.JA().Chrome156()
				}
				client := builder.Build().Unwrap()
				defer client.CloseIdleConnections()
				var body io.Reader
				payload := ""
				if method == http.MethodPost {
					payload = strings.Repeat("request-body", 128)
					body = strings.NewReader(payload)
				}
				// NewRequest provides GetBody for a replayable POST, as required by
				// the transport when retrying a request whose body has been consumed.
				request, err := http.NewRequest(method, ts.URL, body)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.GetClient().Do(request)
				if n := h2Requests.Load(); n != 1 {
					t.Fatalf("expected one HTTP/2 request, got %d", n)
				}
				if !tc.fallback {
					if response != nil {
						response.Body.Close()
					}
					if err == nil {
						t.Fatal("expected the HTTP/2 error to be returned")
					}
					var fallbackErr *surf.ErrHTTP2Fallback
					if errors.As(err, &fallbackErr) {
						t.Fatalf("unexpected HTTP/1.1 fallback: %v", err)
					}
					if n := h1Requests.Load(); n != 0 {
						t.Fatalf("expected no HTTP/1.1 request, got %d", n)
					}
					return
				}
				if err != nil {
					t.Fatalf("expected HTTP/1.1 fallback: %v", err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 {
					t.Fatalf("expected HTTP/1.1 200, got %s %d", response.Proto, response.StatusCode)
				}
				got, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if want := method + "\n" + payload; string(got) != want {
					t.Fatalf("fallback changed method or body: got %q, want %q", got, want)
				}
				if n := h1Requests.Load(); n != 1 {
					t.Fatalf("expected one HTTP/1.1 request, got %d", n)
				}
			})
		}
	}
}

func TestRoundTripperNoHTTP1FallbackOnDialError(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	dialErr := errors.New("injected dial failure")
	client := surf.NewClient().Builder().With(func(c *surf.Client) error {
		c.GetTransport().(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) {
			attempts.Add(1)
			return nil, dialErr
		}
		return nil
	}).JA().Chrome156().Build().Unwrap()
	response := client.Get("https://example.invalid/").Do()
	if !response.IsErr() || !errors.Is(response.Err(), dialErr) {
		t.Fatalf("expected original dial error, got %v", response.Err())
	}
	if n := attempts.Load(); n != 1 {
		t.Fatalf("expected one dial attempt, got %d", n)
	}
}

func TestRoundTripperNoHTTP1FallbackOnProxyConnectError(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if r.Method != http.MethodConnect {
			t.Errorf("expected CONNECT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	client := surf.NewClient().Builder().Proxy(g.String(proxy.URL)).JA().Chrome156().Timeout(3 * time.Second).Build().Unwrap()
	response := client.Get("https://example.invalid/").Do()
	if !response.IsErr() {
		t.Fatal("expected proxy CONNECT error")
	}
	if n := attempts.Load(); n != 1 {
		t.Fatalf("expected one proxy CONNECT, got %d", n)
	}
}

func TestRoundTripperNoHTTP1FallbackOnTLSAlert(t *testing.T) {
	t.Parallel()
	var handshakes atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unexpected HTTP request")
	}))
	ts.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		handshakes.Add(1)
		return nil, errors.New("reject TLS handshake")
	}}
	ts.StartTLS()
	defer ts.Close()
	client := surf.NewClient().Builder().JA().Chrome156().Timeout(3 * time.Second).Build().Unwrap()
	response := client.Get(g.String(ts.URL)).Do()
	if !response.IsErr() {
		t.Fatal("expected TLS alert")
	}
	if n := handshakes.Load(); n != 1 {
		t.Fatalf("expected one TLS handshake, got %d", n)
	}
}
