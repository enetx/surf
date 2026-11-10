package surf_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/enetx/surf/tests/internal/wiretest"
)

func TestFirefoxHTTP1ClientHello(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/wire/firefox_160_http1.json")
	if err != nil {
		t.Fatal(err)
	}
	var reference struct{ TLS string }
	if err := json.Unmarshal(data, &reference); err != nil || reference.TLS == "" {
		t.Fatalf("invalid browser TLS reference: %v", err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer server.Close()
	hellos := make(chan recordedClientHello, 1)
	client := surf.NewClient().Builder().With(func(c *surf.Client) error {
		transport := c.GetTransport().(*http.Transport)
		dial := transport.DialContext
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := dial(ctx, network, server.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			return &clientHelloConn{Conn: conn, hellos: hellos}, nil
		}
		return nil
	}).Impersonate().Windows().Firefox().ForceHTTP1().Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	response := client.Get("https://tls.peet.ws/api/all").Do()
	if response.IsErr() {
		t.Fatal(response.Err())
	}
	if body := response.Ok().Body.String(); body.IsErr() {
		t.Fatal(body.Err())
	}
	select {
	case hello := <-hellos:
		got, _ := wiretest.ClientHello(t, hello.raw, false)
		if got != reference.TLS {
			t.Fatalf("Firefox HTTP/1 ClientHello\n got: %s\nwant: %s", got, reference.TLS)
		}
	default:
		t.Fatal("ClientHello was not recorded")
	}
}

func TestFirefoxHTTP1NavigationHeadersOnWire(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/wire/firefox_160_http1.json")
	if err != nil {
		t.Fatal(err)
	}
	var reference struct {
		Headers []string `json:"headers"`
	}
	if err := json.Unmarshal(data, &reference); err != nil || len(reference.Headers) == 0 {
		t.Fatalf("invalid browser reference: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	captured := make(chan http1WireRequest, 1)
	go captureHTTP1Request(listener, captured)
	client := surf.NewClient().Builder().Impersonate().Windows().Firefox().
		ForceHTTP1().Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	response := client.Get(g.String("http://" + listener.Addr().String() + "/api/all")).Do()
	if response.IsErr() {
		t.Fatal(response.Err())
	}
	if body := response.Ok().Body.String(); body.IsErr() {
		t.Fatal(body.Err())
	}
	got := <-captured
	if got.err != nil {
		t.Fatal(got.err)
	}
	want := append([]string(nil), reference.Headers...)
	want[0] = "Host: " + listener.Addr().String()
	if !reflect.DeepEqual(got.headers, want) {
		t.Fatalf("Firefox HTTP/1 headers\n got: %q\nwant: %q", got.headers, want)
	}
}

func TestFirefoxProtocolHeaderDefaultsAndOverrides(t *testing.T) {
	t.Parallel()
	for _, route := range []string{"plain", "forced", "alpn-fallback", "h2"} {
		for _, overrides := range []string{"default", "explicit", "suppressed"} {
			t.Run(route+"/"+overrides, func(t *testing.T) {
				t.Parallel()
				type observed struct {
					headers http.Header
					major   int
					body    string
				}
				observations := make(chan observed, 1)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					observations <- observed{r.Header.Clone(), r.ProtoMajor, string(body)}
					io.WriteString(w, "ok")
				}))
				server.EnableHTTP2 = route == "h2"
				if route == "plain" {
					server.Start()
				} else {
					server.StartTLS()
				}
				defer server.Close()
				builder := surf.NewClient().Builder().Impersonate().Windows().Firefox().Timeout(5 * time.Second)
				if route == "forced" {
					builder.ForceHTTP1()
				}
				if overrides == "explicit" {
					builder.SetHeaders("TE", "trailers").SetHeaders("Connection", "close")
				} else if overrides == "suppressed" {
					builder.With(func(r *surf.Request) error {
						r.GetRequest().Header["te"] = nil
						r.GetRequest().Header["connection"] = nil
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
				request := client.Post(g.String(server.URL)).Body("profile-body")
				response := request.Do()
				if response.IsErr() {
					t.Fatal(response.Err())
				}
				if body := response.Ok().Body.String(); body.IsErr() {
					t.Fatal(body.Err())
				}
				got := <-observations
				major, te, connection := 1, "", "keep-alive"
				if route == "h2" {
					major, te, connection = 2, "trailers", ""
				}
				if overrides == "explicit" {
					te = "trailers"
					if major == 1 {
						connection = "close"
					}
				} else if overrides == "suppressed" {
					te, connection = "", ""
				}
				if got.major != major || got.headers.Get("TE") != te || got.headers.Get("Connection") != connection || got.body != "profile-body" {
					t.Errorf("observed HTTP/%d TE=%q Connection=%q body=%q; want HTTP/%d TE=%q Connection=%q",
						got.major, got.headers.Get("TE"), got.headers.Get("Connection"), got.body, major, te, connection)
				}
				if !reflect.DeepEqual(request.GetRequest().Header, before) {
					t.Error("protocol defaults mutated the caller's headers")
				}
				for name := range got.headers {
					if strings.Contains(strings.ToLower(name), "header-order") {
						t.Errorf("ordering metadata reached the wire: %q", name)
					}
				}
			})
		}
	}
}
