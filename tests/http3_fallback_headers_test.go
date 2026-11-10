package surf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/enetx/surf/tests/internal/wiretest"
	"golang.org/x/net/http2/hpack"
)

func newHTTPConnectProxy(t *testing.T) *httptest.Server {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusBadRequest)
			return
		}
		upstream, err := net.DialTimeout("tcp", r.Host, 2*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		downstream, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer downstream.Close()
		downstream.SetDeadline(time.Now().Add(5 * time.Second))
		upstream.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffer.Flush(); err != nil {
			return
		}
		go func() { defer upstream.Close(); io.Copy(upstream, buffer) }()
		io.Copy(downstream, upstream)
	}))
	t.Cleanup(proxy.Close)
	return proxy
}

func TestFirefoxHTTP3FallbackPseudoHeadersOnWire(t *testing.T) {
	t.Parallel()
	referenceBytes, err := os.ReadFile("testdata/wire/firefox_160_endpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	var reference struct{ Browser struct{ Hello string } }
	if err := json.Unmarshal(referenceBytes, &reference); err != nil || reference.Browser.Hello == "" {
		t.Fatalf("invalid Firefox browser reference: %v", err)
	}
	// The loopback peer omits DNS SNI. Other normalized ClientHello fields
	// retain the independent browser reference, including ciphers and ALPN.
	wantHello := strings.Replace(reference.Browser.Hello, "extensions 0,", "extensions ", 1)
	wantHello = strings.Join(slices.DeleteFunc(strings.Split(wantHello, "\n"), func(line string) bool {
		return strings.HasPrefix(line, "ext 0:")
	}), "\n")
	for _, route := range []string{"http2", "proxy", "quic-timeout", "quic-racing"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			for _, explicit := range []bool{false, true} {
				name := route + "/" + method
				if explicit {
					name += "/custom-order"
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					type observation struct {
						fields []hpack.HeaderField
						body   string
					}
					captured := make(chan observation, 1)
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						t.Error("unexpected HTTP/1 fallback")
						w.WriteHeader(http.StatusBadRequest)
					}))
					server.EnableHTTP2 = true
					server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
						"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
							defer conn.Close()
							conn.SetDeadline(time.Now().Add(5 * time.Second))
							preface := make([]byte, len(http2.ClientPreface))
							if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
								return
							}
							fr := http2.NewFramer(conn, conn)
							fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
							if err := fr.WriteSettings(); err != nil {
								return
							}
							var got observation
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
										fr.WriteSettingsAck()
									}
								case *http2.MetaHeadersFrame:
									got.fields = slices.Clone(f.Fields)
									streamID, ended = f.StreamID, f.StreamEnded()
								case *http2.DataFrame:
									got.body += string(f.Data())
									ended = f.StreamID == streamID && f.StreamEnded()
								}
								if !ended {
									continue
								}
								captured <- got
								var block bytes.Buffer
								hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
								fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true})
								return
							}
						},
					}
					server.StartTLS()
					defer server.Close()
					builder := surf.NewClient().Builder().Impersonate().Windows().Firefox().
						TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second)
					if route == "http2" {
						builder.ForceHTTP2()
					} else {
						builder.ForceHTTP3()
						if route == "proxy" {
							builder.Proxy(g.String(newHTTPConnectProxy(t).URL))
						} else {
							builder.QUICSettings().HandshakeIdleTimeout(30 * time.Millisecond).Set()
							if route == "quic-racing" {
								builder.HTTP3Settings().ConnectionRacing(true).TCPFallbackDelay(0).Set()
							}
						}
					}
					hellos := make(chan recordedClientHello, 4)
					builder.With(func(c *surf.Client) error {
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
					}, 1)
					want := []string{":method", ":path", ":authority", ":scheme"}
					if explicit {
						want = []string{":scheme", ":path", ":method", ":authority"}
						builder.With(func(r *surf.Request) error {
							r.GetRequest().Header[http.PHeaderOrderKey] = slices.Clone(want)
							return nil
						}, 10)
					}
					var before http.Header
					builder.With(func(r *surf.Request) error {
						before = r.GetRequest().Header.Clone()
						return nil
					}, 1000)
					client := builder.Build().Unwrap()
					defer client.Close()
					request := client.Get(g.String(server.URL))
					payload := ""
					if method == http.MethodPost {
						payload = "fallback-body"
						request = client.Post(g.String(server.URL)).Body(payload)
					}
					response := request.Do()
					if response.IsErr() {
						t.Fatal(response.Err())
					}
					if body := response.Ok().Body.String(); body.IsErr() {
						t.Fatal(body.Err())
					}
					if response.Ok().GetResponse().ProtoMajor != 2 {
						t.Fatal("request did not use HTTP/2")
					}
					got := <-captured
					var order []string
					var te string
					for _, field := range got.fields {
						if strings.HasPrefix(field.Name, ":") {
							order = append(order, field.Name)
						}
						if field.Name == "te" {
							te = field.Value
						}
						if field.Name == "connection" || field.Name == "alt-used" {
							t.Errorf("other protocol's default reached HTTP/2: %q", field.Name)
						}
					}
					if !slices.Equal(order, want) || got.body != payload || te != "trailers" {
						t.Errorf("HTTP/2: pseudo=%v body=%q TE=%q; want pseudo=%v body=%q TE=trailers", order, got.body, te, want, payload)
					}
					if !reflect.DeepEqual(request.GetRequest().Header, before) {
						t.Error("transport defaults mutated request headers")
					}
					select {
					case hello := <-hellos:
						gotHello, _ := wiretest.ClientHello(t, hello.raw, false)
						if gotHello != wantHello {
							t.Fatalf("TCP fallback lost browser TLS profile\n got: %s\nwant: %s", gotHello, wantHello)
						}
					default:
						t.Fatal("no TCP ClientHello captured")
					}
				})
			}
		}
	}
}

func TestFirefoxHTTP3ExplicitPseudoHeaderOrderOnWire(t *testing.T) {
	t.Parallel()
	peer := newH3Peer(t)
	want := []string{":scheme", ":path", ":method", ":authority"}
	client := surf.NewClient().Builder().Impersonate().Windows().Firefox().ForceHTTP3().
		With(func(r *surf.Request) error {
			r.GetRequest().Header[http.PHeaderOrderKey] = slices.Clone(want)
			return nil
		}, 10).TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	response := client.Get(g.String(peer.url)).Do().Unwrap()
	if body := response.Body.String(); body.IsErr() {
		t.Fatal(body.Err())
	}
	select {
	case request := <-peer.requests:
		var order []string
		for _, field := range request.headers {
			if strings.HasPrefix(field.Name, ":") {
				order = append(order, field.Name)
			}
		}
		if !slices.Equal(order, want) {
			t.Fatalf("explicit HTTP/3 pseudo-header order = %v, want %v", order, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no HTTP/3 request captured")
	}
}

func TestHTTP3FallbackReplacesEarlierTLSProfile(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"firefox", "chrome"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			recorder := newHelloRecorder(t)
			profile := surf.NewClient().Builder().Impersonate().Windows()
			var b *surf.Builder
			want := []uint16{23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037}
			if name == "firefox" {
				b = profile.Firefox().ForceHTTP3()
				b.JA().Chrome156()
				b.JA().Firefox160()
			} else {
				b = profile.Chrome().ForceHTTP3()
				b.JA().Firefox160()
				b.JA().Chrome156()
				// Independent Chrome 156 navigation golden, without DNS SNI.
				want = []uint16{10, 11, 13, 16, 17613, 18, 23, 27, 35, 43, 45, 5, 51, 51764, 65037, 65281, 0x0a0a, 0x0a0a}
			}
			b.QUICSettings().HandshakeIdleTimeout(30 * time.Millisecond).Set()
			client := b.Timeout(3 * time.Second).Build().Unwrap()
			defer client.Close()
			// The recorder closes after ClientHello; only the final TCP profile matters.
			client.Get(recorder.url()).Do()
			recorder.mu.Lock()
			defer recorder.mu.Unlock()
			if len(recorder.hellos) != 1 {
				t.Fatalf("expected one TCP ClientHello, got %d", len(recorder.hellos))
			}
			got := slices.Clone(recorder.hellos[0])
			if name == "chrome" {
				for i, id := range got {
					if isGREASE(id) {
						got[i] = 0x0a0a
					}
				}
				slices.Sort(got)
				slices.Sort(want)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("fallback did not select the final %s profile: got %v, want %v", name, got, want)
			}
		})
	}
}

func TestFirefoxHTTP3FallbackToHTTP1Defaults(t *testing.T) {
	t.Parallel()
	headers := make(chan http.Header, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		io.Copy(w, r.Body)
	}))
	defer server.Close()
	client := surf.NewClient().Builder().Impersonate().Windows().Firefox().ForceHTTP3().
		Proxy(g.String(newHTTPConnectProxy(t).URL)).TLSConfig(&tls.Config{InsecureSkipVerify: true}).
		Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	response := client.Post(g.String(server.URL)).Body("fallback-body").Do().Unwrap()
	if body := response.Body.String(); body.IsErr() || body.Ok() != "fallback-body" {
		t.Fatalf("unexpected fallback response: %v", body)
	}
	got := <-headers
	if response.GetResponse().ProtoMajor != 1 || got.Get("Connection") != "keep-alive" || got.Get("TE") != "" || got.Get("Alt-Used") != "" {
		t.Fatalf("HTTP/3 -> HTTP/1 defaults: protocol=%s headers=%v", response.GetResponse().Proto, got)
	}
}

func TestHTTP3CloseClosesTCPFallbackConnections(t *testing.T) {
	t.Parallel()
	closed := make(chan struct{}, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := surf.NewClient().Builder().Impersonate().Windows().Firefox().ForceHTTP3().
		Proxy(g.String(newHTTPConnectProxy(t).URL)).TLSConfig(&tls.Config{InsecureSkipVerify: true}).
		Timeout(3 * time.Second).Build().Unwrap()
	defer client.Close()
	response := client.Get(g.String(server.URL)).Do().Unwrap()
	if body := response.Body.String(); body.IsErr() {
		t.Fatal(body.Err())
	}
	if response.GetResponse().ProtoMajor != 2 {
		t.Fatal("request did not use TCP fallback")
	}
	client.Close()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/3 client Close left its TCP fallback connection open")
	}
}
