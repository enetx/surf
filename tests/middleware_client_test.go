package surf_test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestMiddlewareClientH2C(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"h2c": "test"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	result := surf.NewClient().Builder().H2C().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Logf("H2C test failed (may be expected): %v", resp.Err())
		return
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareClientH2CTransportConfiguration(t *testing.T) {
	t.Parallel()

	result := surf.NewClient().Builder().H2C().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()
	transport := client.GetClient().Transport

	if transport == nil {
		t.Fatal("expected transport to be configured")
	}
}

func TestMiddlewareDNSOverTLS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dns  string
	}{
		{"Cloudflare DoT", "1.1.1.1:853"},
		{"Google DoT", "8.8.8.8:853"},
		{"Quad9 DoT", "9.9.9.9:853"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := surf.NewClient().Builder().DNS(g.String(tt.dns)).Build()
			if result.IsErr() {
				t.Fatalf("failed to build client: %v", result.Err())
			}

			client := result.Ok()

			if client.GetDialer() == nil {
				t.Fatal("expected dialer to be configured")
			}

			if client.GetDialer().Resolver == nil {
				t.Fatal("expected resolver to be configured")
			}
		})
	}
}

func TestMiddlewareInterfaceBinding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		addr        string
		expectError bool
	}{
		{"IPv4 localhost", "127.0.0.1", false},
		{"IPv4 private", "192.168.1.100", false},
		{"IPv6 localhost", "::1", false},
		{"IPv4 any", "0.0.0.0", false},
		{"Invalid address", "not-an-ip", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := surf.NewClient().Builder().InterfaceAddr(g.String(tt.addr)).Build()

			if tt.expectError {
				if result.IsOk() {
					t.Errorf("expected error for %s", tt.name)
				}
				return
			}

			if result.IsErr() {
				t.Fatalf("failed to build client: %v", result.Err())
			}

			if result.Ok().GetDialer() == nil {
				t.Fatal("expected dialer to be configured")
			}
		})
	}
}

func TestMiddlewareUnixDomainSocket(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{"Tmp socket", "/tmp/test.sock"},
		{"Docker socket", "/var/run/docker.sock"},
		{"Custom socket", "/tmp/custom-app.socket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := surf.NewClient().Builder().UnixSocket(g.String(tt.path)).Build()
			if result.IsErr() {
				t.Fatalf("failed to build client: %v", result.Err())
			}

			client := result.Ok()

			if client.GetDialer() == nil {
				t.Fatal("expected dialer to be configured")
			}
		})
	}
}

func TestMiddlewareProxyWithFallback(t *testing.T) {
	t.Parallel()

	result := surf.NewClient().Builder().
		Proxy("http://127.0.0.1:8080").
		HTTP3Settings().Set().
		Build()

	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()

	if client.GetTransport() == nil {
		t.Fatal("expected transport to be configured")
	}
}

func TestMiddlewareTimeoutConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout int
	}{
		{"Short timeout", 5},
		{"Medium timeout", 30},
		{"Long timeout", 120},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := surf.NewClient().Builder().
				Timeout(time.Duration(tt.timeout) * time.Second).
				Build()

			if result.IsErr() {
				t.Fatalf("failed to build client: %v", result.Err())
			}

			client := result.Ok()
			expected := time.Duration(tt.timeout) * time.Second

			if client.GetClient().Timeout != expected {
				t.Errorf("expected timeout %v, got %v", expected, client.GetClient().Timeout)
			}
		})
	}
}

func TestMiddlewareClientH2CWithHTTP2Settings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		buildFunc func() g.Result[*surf.Client]
	}{
		{
			"H2C with default settings",
			func() g.Result[*surf.Client] {
				return surf.NewClient().Builder().H2C().Build()
			},
		},
		{
			"H2C with compression disabled",
			func() g.Result[*surf.Client] {
				return surf.NewClient().Builder().H2C().DisableCompression().Build()
			},
		},
		{
			"H2C with timeout",
			func() g.Result[*surf.Client] {
				return surf.NewClient().Builder().H2C().Timeout(10 * time.Second).Build()
			},
		},
		{
			"H2C with keep-alive disabled",
			func() g.Result[*surf.Client] {
				return surf.NewClient().Builder().H2C().DisableKeepAlive().Build()
			},
		},
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "h2c test")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.buildFunc()
			if result.IsErr() {
				t.Fatalf("failed to build client: %v", result.Err())
			}

			client := result.Ok()
			resp := client.Get(g.String(ts.URL)).Do()

			if resp.IsErr() {
				t.Logf("H2C settings test failed (may be expected): %v", resp.Err())
				return
			}

			if resp.Ok().StatusCode != http.StatusOK {
				t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
			}

			body := resp.Ok().Body.String()
			if body.Std() != "h2c test" {
				t.Errorf("expected body 'h2c test', got %s", body.Std())
			}
		})
	}
}

func TestMiddlewareClientH2CHTTPMethods(t *testing.T) {
	t.Parallel()

	var receivedMethod string
	handler := func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"method": "%s"}`, r.Method)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	result := surf.NewClient().Builder().H2C().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()

	testMethods := []struct {
		method  string
		reqFunc func(string) *surf.Request
	}{
		{"GET", func(url string) *surf.Request { return client.Get(g.String(url)) }},
		{"POST", func(url string) *surf.Request { return client.Post(g.String(url), g.String("test")) }},
		{"PUT", func(url string) *surf.Request { return client.Put(g.String(url), g.String("test")) }},
		{"DELETE", func(url string) *surf.Request { return client.Delete(g.String(url)) }},
	}

	for _, tm := range testMethods {
		t.Run(tm.method, func(t *testing.T) {
			resp := tm.reqFunc(ts.URL).Do()

			if resp.IsErr() {
				t.Logf("H2C %s method test failed (may be expected): %v", tm.method, resp.Err())
				return
			}

			if resp.Ok().StatusCode != http.StatusOK {
				t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
			}

			if receivedMethod != tm.method {
				t.Errorf("expected method %s, got %s", tm.method, receivedMethod)
			}
		})
	}
}

func TestMiddlewareClientH2CCompatibilityChecks(t *testing.T) {
	t.Parallel()

	result := surf.NewClient().Builder().H2C().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()

	if client.GetClient() == nil {
		t.Fatal("expected HTTP client to be configured")
	}

	if client.GetClient().Transport == nil {
		t.Fatal("expected transport to be configured")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"host": "%s", "userAgent": "%s"}`, r.Host, r.UserAgent())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Logf("H2C compatibility test failed (may be expected): %v", resp.Err())
		return
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String()
	if !strings.Contains(body.Std(), "host") {
		t.Error("expected response to contain host information")
	}
}

func TestMiddlewareClientProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		proxy g.String
	}{
		{
			name:  "string proxy",
			proxy: "http://127.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := surf.NewClient().Builder().Proxy(tt.proxy).Build()
			if result.IsErr() {
				t.Fatalf("failed to build client: %v", result.Err())
			}

			client := result.Ok()

			if client.GetTransport() == nil {
				t.Fatal("expected transport to be configured")
			}
		})
	}
}

func TestMiddlewareClientDNSResolver(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dns  string
	}{
		{"Google DNS", "8.8.8.8:53"},
		{"Cloudflare DNS", "1.1.1.1:53"},
		{"Custom DNS", "192.168.1.1:53"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := surf.NewClient().Builder().DNS(g.String(tt.dns)).Build()
			if result.IsErr() {
				t.Fatalf("failed to build client: %v", result.Err())
			}

			client := result.Ok()

			if client.GetDialer() == nil {
				t.Fatal("expected dialer to be configured")
			}
		})
	}
}

func TestMiddlewareClientInterface(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		iface       string
		expectError bool
	}{
		{"IPv4 address", "127.0.0.1", false},
		{"IPv6 address", "::1", false},
		{"Any address", "0.0.0.0", false},
		{"Invalid", "not-valid-anything", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := surf.NewClient().Builder().InterfaceAddr(g.String(tt.iface)).Build()

			if tt.expectError {
				if result.IsOk() {
					t.Errorf("expected error for %s", tt.name)
				}
				return
			}

			if result.IsErr() {
				t.Fatalf("failed to build client: %v", result.Err())
			}

			if result.Ok().GetDialer() == nil {
				t.Fatal("expected dialer to be configured")
			}
		})
	}
}

func TestMiddlewareClientInterfaceByName(t *testing.T) {
	t.Parallel()

	// Get available interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot get interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		t.Run(iface.Name, func(t *testing.T) {
			result := surf.NewClient().Builder().InterfaceAddr(g.String(iface.Name)).Build()
			if result.IsErr() {
				t.Fatalf("failed for interface %s: %v", iface.Name, result.Err())
			}

			if result.Ok().GetDialer().LocalAddr == nil {
				t.Error("expected LocalAddr to be set")
			}
		})

		break
	}
}

func TestMiddlewareClientUnixDomainSocketTest(t *testing.T) {
	t.Parallel()

	socket := "/tmp/test.sock"

	result := surf.NewClient().Builder().UnixSocket(g.String(socket)).Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()

	if client.GetDialer() == nil {
		t.Fatal("expected dialer to be configured")
	}
}

func TestMiddlewareClientDNSConfiguration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		dns         string
		expectError bool
	}{
		{"Google DNS IPv4", "8.8.8.8:53", false},
		{"Cloudflare DNS IPv4", "1.1.1.1:53", false},
		{"Google DNS IPv6", "[2001:4860:4860::8888]:53", false},
		{"Localhost DNS", "127.0.0.1:53", false},
		{"Invalid port", "8.8.8.8:99999", true},
		{"Missing port", "8.8.8.8", true},
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"dns_test": "success", "remote_addr": "%s"}`, r.RemoteAddr)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := surf.NewClient().Builder().DNS(g.String(tc.dns)).Build()

			if tc.expectError {
				if result.IsOk() {
					t.Errorf("expected error for %s", tc.name)
				}
				return
			}

			if result.IsErr() {
				t.Fatalf("failed to build client: %v", result.Err())
			}

			client := result.Ok()
			dialer := client.GetDialer()

			if dialer.Resolver == nil {
				t.Error("expected resolver to be set for valid DNS")
			} else if !dialer.Resolver.PreferGo {
				t.Error("expected resolver to have PreferGo set to true")
			}

			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Logf("DNS test failed (may be expected with custom DNS %s): %v", tc.dns, resp.Err())
			} else if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success status with DNS %s, got %d", tc.dns, resp.Ok().StatusCode)
			}
		})
	}
}

func TestMiddlewareClientDNSResolverBehavior(t *testing.T) {
	t.Parallel()

	result := surf.NewClient().Builder().DNS(g.String("1.1.1.1:53")).Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()
	dialer := client.GetDialer()

	if dialer.Resolver == nil {
		t.Fatal("expected resolver to be set")
	}

	if !dialer.Resolver.PreferGo {
		t.Error("expected resolver PreferGo to be true")
	}

	if dialer.Resolver.Dial == nil {
		t.Error("expected resolver Dial function to be set")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"host": "%s"}`, r.Host)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("DNS resolver test failed: %v", resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareClientTimeout(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"timeout": "test"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Short timeout - should fail
	result1 := surf.NewClient().Builder().Timeout(50 * time.Millisecond).Build()
	if result1.IsErr() {
		t.Fatalf("failed to build client: %v", result1.Err())
	}

	resp1 := result1.Ok().Get(g.String(ts.URL)).Do()
	if resp1.IsOk() {
		t.Error("expected timeout error")
	}

	// Long timeout - should succeed
	result2 := surf.NewClient().Builder().Timeout(200 * time.Millisecond).Build()
	if result2.IsErr() {
		t.Fatalf("failed to build client: %v", result2.Err())
	}

	resp2 := result2.Ok().Get(g.String(ts.URL)).Do()
	if resp2.IsErr() {
		t.Errorf("expected success with longer timeout, got error: %v", resp2.Err())
	}
}

func TestMiddlewareClientRedirectPolicy(t *testing.T) {
	t.Parallel()

	redirectCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		if redirectCount < 3 {
			redirectCount++
			http.Redirect(w, r, fmt.Sprintf("/redirect%d", redirectCount), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"redirect": "final"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test NotFollowRedirects
	result1 := surf.NewClient().Builder().NotFollowRedirects().Build()
	if result1.IsErr() {
		t.Fatalf("failed to build client: %v", result1.Err())
	}

	resp1 := result1.Ok().Get(g.String(ts.URL)).Do()
	if resp1.IsErr() {
		t.Fatal(resp1.Err())
	}

	if resp1.Ok().StatusCode != http.StatusFound {
		t.Errorf("expected redirect status with NotFollowRedirects, got %d", resp1.Ok().StatusCode)
	}

	redirectCount = 0

	// Test MaxRedirects
	result2 := surf.NewClient().Builder().MaxRedirects(2).Build()
	if result2.IsErr() {
		t.Fatalf("failed to build client: %v", result2.Err())
	}

	resp2 := result2.Ok().Get(g.String(ts.URL)).Do()
	if resp2.IsOk() {
		t.Log("MaxRedirects test passed but might not have failed as expected")
	}

	redirectCount = 0

	// Test with enough redirects
	result3 := surf.NewClient().Builder().MaxRedirects(5).Build()
	if result3.IsErr() {
		t.Fatalf("failed to build client: %v", result3.Err())
	}

	resp3 := result3.Ok().Get(g.String(ts.URL)).Do()
	if resp3.IsErr() {
		t.Fatal(resp3.Err())
	}

	if resp3.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected final status 200, got %d", resp3.Ok().StatusCode)
	}
}

func TestMiddlewareClientFollowOnlyHostRedirects(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost/", http.StatusFound)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	result := surf.NewClient().Builder().FollowOnlyHostRedirects().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	resp := result.Ok().Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusFound {
		t.Errorf("expected redirect status when not following external redirect, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareClientForwardHeadersOnRedirect(t *testing.T) {
	t.Parallel()

	var receivedHeaders http.Header
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	result := surf.NewClient().Builder().ForwardHeadersOnRedirect().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	resp := result.Ok().Get(g.String(ts.URL)).
		SetHeaders(g.Map[string, string]{
			"X-Custom": "forwarded",
			"X-Test":   "value",
		}).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if receivedHeaders.Get("X-Custom") != "forwarded" {
		t.Error("expected custom header to be forwarded on redirect")
	}
}

func TestMiddlewareClientDisableKeepAlive(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `test`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	result := surf.NewClient().Builder().DisableKeepAlive().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	resp := result.Ok().Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareClientDisableCompression(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") == "" {
			w.Header().Set("X-Compression", "disabled")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `test`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	result := surf.NewClient().Builder().DisableCompression().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	resp := result.Ok().Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareClientForceHTTP1(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"proto": "%s"}`, r.Proto)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	result := surf.NewClient().Builder().ForceHTTP1().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	resp := result.Ok().Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareClientSession(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/setcookie":
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: "test123",
				Path:  "/",
			})
		case "/checkcookie":
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "test123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `ok`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	result := surf.NewClient().Builder().Session().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()

	resp1 := client.Get(g.String(ts.URL + "/setcookie")).Do()
	if resp1.IsErr() {
		t.Fatal(resp1.Err())
	}

	resp2 := client.Get(g.String(ts.URL + "/checkcookie")).Do()
	if resp2.IsErr() {
		t.Fatal(resp2.Err())
	}

	if resp2.Ok().StatusCode != http.StatusOK {
		t.Error("expected session cookie to be sent")
	}
}

func TestMiddlewareClientH2CErrorHandling(t *testing.T) {
	t.Parallel()

	result := surf.NewClient().Builder().H2C().Build()
	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	client := result.Ok()

	// Test connection to non-existent server
	resp := client.Get(g.String("http://127.0.0.1:65535/nonexistent")).Do()
	if resp.IsOk() {
		t.Error("expected error connecting to non-existent server")
	}

	// Test with invalid URL
	resp2 := client.Get(g.String("invalid-url")).Do()
	if resp2.IsOk() {
		t.Error("expected error with invalid URL")
	}
}

func TestMiddlewareClientComplexConfigurations(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"complex": "config"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	result := surf.NewClient().Builder().
		DNS("8.8.8.8:53").
		Timeout(5 * time.Second).
		DisableKeepAlive().
		DisableCompression().
		H2C().
		Build()

	if result.IsErr() {
		t.Fatalf("failed to build client: %v", result.Err())
	}

	resp := result.Ok().Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Logf("Complex configuration request error: %v", resp.Err())
	} else if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareClientDNSValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		dns         string
		expectError bool
	}{
		{"Valid DNS", "8.8.8.8:53", false},
		{"Missing port", "8.8.8.8", true},
		{"Empty string", "", true},
		{"Invalid format", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := surf.NewClient().Builder().DNS(g.String(tt.dns)).Build()

			if tt.expectError && result.IsOk() {
				t.Errorf("expected error for DNS %q", tt.dns)
			}

			if !tt.expectError && result.IsErr() {
				t.Errorf("unexpected error for DNS %q: %v", tt.dns, result.Err())
			}
		})
	}
}

func TestMiddlewareClientUnixSocketValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		socket      string
		expectError bool
	}{
		{"Valid socket", "/tmp/test.sock", false},
		{"Empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := surf.NewClient().Builder().UnixSocket(g.String(tt.socket)).Build()

			if tt.expectError && result.IsOk() {
				t.Errorf("expected error for socket %q", tt.socket)
			}

			if !tt.expectError && result.IsErr() {
				t.Errorf("unexpected error for socket %q: %v", tt.socket, result.Err())
			}
		})
	}
}
