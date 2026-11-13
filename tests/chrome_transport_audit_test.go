package surf_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/tests/internal/wiretest"
)

type chromeH1Observation struct{ raw, body string }

func chromeH1Peer(t *testing.T) (string, <-chan chromeH1Observation, <-chan bool) {
	t.Helper()
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	config := seed.TLS.Clone()
	seed.Close()
	config.NextProtos = []string{"http/1.1"}
	hellos := make(chan bool, 16)
	config.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		grease := len(h.CipherSuites) > 0 && h.CipherSuites[0]&0x0f0f == 0x0a0a
		select {
		case hellos <- grease:
		default:
		}
		return nil, nil
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	observations := make(chan chromeH1Observation, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(conn)
				var raw strings.Builder
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					raw.WriteString(line)
					if line == "\r\n" {
						break
					}
				}
				request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw.String())))
				if err != nil {
					return
				}
				body := make([]byte, request.ContentLength)
				if _, err = io.ReadFull(r, body); err != nil {
					return
				}
				observations <- chromeH1Observation{raw: raw.String(), body: string(body)}
				io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}()
		}
	}()
	return ln.Addr().String(), observations, hellos
}

func assertChromeH1(t *testing.T, got chromeH1Observation, explicit bool) {
	t.Helper()
	lines := strings.Split(got.raw, "\r\n")
	const clientHints = `sec-ch-ua: "Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"`
	if !strings.Contains(got.raw, "\r\n"+clientHints+"\r\n") {
		t.Errorf("Chrome 158 Client Hints missing from HTTP/1 request: %s", got.raw)
	}
	if len(lines) < 4 || !strings.HasPrefix(lines[1], "Host: ") || lines[2] != "Connection: keep-alive" {
		t.Fatalf("Chrome HTTP/1 field prefix: %q", lines[:min(4, len(lines))])
	}
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "sec-ch-ua") && !strings.HasPrefix(line, "sec-ch-ua") {
			t.Errorf("Client Hint case: %q", line)
		}
	}
	priority := strings.Contains(strings.ToLower(got.raw), "\r\npriority:")
	if priority != explicit {
		t.Errorf("Priority present=%v explicit=%v: %s", priority, explicit, got.raw)
	}
	if explicit && !strings.Contains(got.raw, "u=6") {
		t.Error("explicit Priority was replaced")
	}
}

func TestChromeHTTP1HeadersForSelectedTransport(t *testing.T) {
	for _, route := range []string{"forced", "alpn-fallback", "quic-fallback"} {
		for _, method := range []string{"GET", "POST"} {
			for _, explicit := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", route, method, explicit), func(t *testing.T) {
					addr, observations, _ := chromeH1Peer(t)
					b := surf.NewClient().Builder().Impersonate().Windows().Chrome().Proxy("").Timeout(5 * time.Second)
					if route == "forced" {
						b.ForceHTTP1()
					} else if route == "quic-fallback" {
						b.ForceHTTP3().QUICSettings().HandshakeIdleTimeout(25 * time.Millisecond).Set()
					} else {
						b.HTTP3Settings().Discovery(false).Set()
					}
					c := b.Build().Unwrap()
					defer c.Close()
					req := c.Get(g.String("https://" + addr + "/audit"))
					if method == "POST" {
						req = c.Post(g.String("https://" + addr + "/audit")).Body("payload")
					}
					if explicit {
						req.SetHeaders(g.Map[string, string]{header.PRIORITY: "u=6"})
					}
					response := req.Do()
					if response.IsErr() {
						t.Fatal(response.Err())
					}
					response.Unwrap().Body.String().Unwrap()
					select {
					case got := <-observations:
						assertChromeH1(t, got, explicit)
						if method == "POST" && got.body != "payload" {
							t.Errorf("body %q", got.body)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("request not captured")
					}
				})
			}
		}
	}
}

func TestChromeProxyEnvironmentFingerprint(t *testing.T) {
	if os.Getenv("SURF_CHROME_PROXY_HELPER") == "" {
		for _, route := range []string{"environment", "explicit", "direct", "clear-proxy", "no-proxy", "h3-environment", "selector"} {
			t.Run(route, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestChromeProxyEnvironmentFingerprint$")
				for _, entry := range os.Environ() {
					key, _, _ := strings.Cut(entry, "=")
					switch strings.ToUpper(key) {
					case "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "SURF_CHROME_PROXY_HELPER":
						continue
					}
					cmd.Env = append(cmd.Env, entry)
				}
				cmd.Env = append(cmd.Env, "SURF_CHROME_PROXY_HELPER="+route)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("proxy child: %v\n%s", err, output)
				}
			})
		}
		return
	}
	route := os.Getenv("SURF_CHROME_PROXY_HELPER")
	addr, observations, hellos := chromeH1Peer(t)
	var tunnels atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			w.WriteHeader(405)
			return
		}
		target, err := net.Dial("tcp", addr)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		tunnels.Add(1)
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			target.Close()
			return
		}
		io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { defer client.Close(); defer target.Close(); io.Copy(target, client) }()
		io.Copy(client, target)
	}))
	defer proxy.Close()
	environment := proxy.URL
	if route == "explicit" || route == "direct" {
		environment = "http://127.0.0.1:1"
	}
	t.Setenv("HTTPS_PROXY", environment)
	t.Setenv("NO_PROXY", "")
	if route == "no-proxy" {
		t.Setenv("NO_PROXY", "origin.example")
	}
	b := surf.NewClient().Builder().Impersonate().Windows().Chrome().Timeout(5 * time.Second)
	// This peer is local and tests proxy routing, not public HTTPS DNS. Discovery
	// must not let an external resolver delay the custom dialer's direct route.
	b.HTTP3Settings().HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
		return nil, nil
	}).Set()
	if route == "h3-environment" || route == "selector" {
		b.ForceHTTP3()
		b.HTTP3Settings().HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
			t.Error("proxy request attempted local HTTPS discovery")
			return nil, nil
		}).Set()
	} else {
		b.ForceHTTP1()
	}
	if route == "explicit" {
		b.Proxy(g.String(proxy.URL))
	}
	if route == "clear-proxy" {
		b.Proxy("http://127.0.0.1:1").Proxy("")
	}
	if route == "direct" {
		b.Proxy("")
	}
	if route == "direct" || route == "clear-proxy" || route == "no-proxy" {
		b.With(func(c *surf.Client) error {
			tr := c.GetTransport().(*http.Transport)
			dial := tr.DialContext
			tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) { return dial(ctx, network, addr) }
			return nil
		}, 1)
	}
	var selections atomic.Int32
	if route == "selector" {
		b.With(func(c *surf.Client) error {
			c.GetTransport().(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) {
				if selections.Add(1) > 1 {
					return url.Parse("http://127.0.0.1:1")
				}
				return url.Parse(proxy.URL)
			}
			return nil
		}, 1)
	}
	c := b.Build().Unwrap()
	defer c.Close()
	result := c.Get("https://origin.example/audit").Do()
	if result.IsErr() {
		t.Fatal(result.Err())
	}
	result.Unwrap().Body.String().Unwrap()
	got := <-observations
	assertChromeH1(t, got, false)
	select {
	case grease := <-hellos:
		if !grease {
			t.Fatal("proxy substituted native Go TLS for Chrome")
		}
	default:
		t.Fatal("no TLS ClientHello")
	}
	want := int32(1)
	if route == "h3-environment" || route == "selector" {
		want = 2 // ALPN fallback prepares a separate HTTP/1 connection.
	}
	if route == "direct" || route == "clear-proxy" || route == "no-proxy" {
		want = 0
	}
	if route == "selector" && selections.Load() != 1 {
		t.Errorf("proxy selector called %d times", selections.Load())
	}
	if tunnels.Load() != want {
		t.Errorf("proxy tunnels %d want %d", tunnels.Load(), want)
	}
}

func TestChrome158TCPClientHelloMatchesRetainedNativeShape(t *testing.T) {
	data, err := os.ReadFile("testdata/wire/chrome-158-windows.golden")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "## tcp client hello (h2)\n")
	if !ok {
		t.Fatal("missing native hello")
	}
	want, _, _ := strings.Cut(rest, "\n## http/2 navigation")
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	peer.EnableHTTP2 = true
	peer.StartTLS()
	defer peer.Close()
	hellos := make(chan recordedClientHello, 1)
	client := surf.NewClient().Builder().Impersonate().Windows().Chrome().Proxy("").ForceHTTP2().With(func(c *surf.Client) error {
		tr := c.GetTransport().(*http.Transport)
		dial := tr.DialContext
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &clientHelloConn{Conn: conn, hellos: hellos}, nil
		}
		return nil
	}, 1).Build().Unwrap()
	defer client.Close()
	response := client.Get(g.String(peer.URL)).Do().Unwrap()
	response.Body.String().Unwrap()
	select {
	case hello := <-hellos:
		got, _ := wiretest.ClientHello(t, hello.raw, true)
		if got != want {
			t.Fatalf("Chrome 158 retained native TLS shape mismatch\n%s\nwant:\n%s", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no ClientHello")
	}
}

func TestChromeProxyPoolsRemainSeparateAndFrozen(t *testing.T) {
	peer := newDiscoveryPeer(t, nil)
	var useProxy atomic.Bool
	proxy := newHTTPConnectProxy(t)
	proxyURL, _ := url.Parse(proxy.URL)
	b := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP2().With(func(c *surf.Client) error {
		c.GetTransport().(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) {
			if useProxy.Load() {
				return proxyURL, nil
			}
			return nil, nil
		}
		return nil
	}, 1).TLSConfig(&tls.Config{RootCAs: peer.roots, ServerName: "example.com"}).Timeout(5 * time.Second)
	client := b.Build().Unwrap()
	defer client.Close()
	var addresses []string
	for i := 0; i < 3; i++ {
		useProxy.Store(i == 1)
		if i == 1 {
			b.HTTP2Settings().InitialStreamID(2)
		}
		result := client.Get(g.String(peer.tcp.URL)).Do()
		if result.IsErr() {
			t.Fatal(result.Err())
		}
		response := result.Unwrap()
		response.Body.String().Unwrap()
		if response.GetResponse().ProtoMajor != 2 {
			t.Fatal("lost HTTP/2 profile")
		}
		request := <-peer.requests
		addresses = append(addresses, request.RemoteAddr)
	}
	if addresses[0] == addresses[1] {
		t.Fatal("proxy reused the direct connection")
	}
	if addresses[0] != addresses[2] {
		t.Fatal("returning to direct lost its own connection pool")
	}
}

func TestChromeProxyRoutingRetainsKnownECH(t *testing.T) {
	list, key := testECHConfig(t)
	peer := newDiscoveryPeer(t, []tls.EncryptedClientHelloKey{key})
	var useProxy atomic.Bool
	proxy := newHTTPConnectProxy(t)
	proxyURL, _ := url.Parse(proxy.URL)
	port, _ := strconv.ParseUint(peer.port, 10, 16)
	client := surf.NewClient().Builder().Impersonate().Chrome().With(func(c *surf.Client) error {
		c.GetTransport().(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) {
			if useProxy.Load() {
				return proxyURL, nil
			}
			return nil, nil
		}
		return nil
	}, 1).
		HTTP3Settings().HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
		return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", Port: uint16(port), ALPN: []string{"h3", "h2"}, TTL: time.Minute, ECH: list}}, nil
	}).Set().TLSConfig(&tls.Config{RootCAs: peer.roots}).Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	for i := 0; i < 2; i++ {
		useProxy.Store(i == 1)
		result := client.Get("https://example.com/").Do()
		if result.IsErr() {
			t.Fatal(result.Err())
		}
		response := result.Unwrap()
		response.Body.String().Unwrap()
		request := <-peer.requests
		if !request.TLS.ECHAccepted {
			t.Fatal("routing change dropped ECH")
		}
		if request.Host != "example.com" || request.TLS.ServerName != "example.com" {
			t.Fatal("routing change replaced the origin")
		}
		if i == 1 && response.GetResponse().ProtoMajor != 2 {
			t.Fatal("TCP proxy did not select HTTP/2")
		}
	}
}
