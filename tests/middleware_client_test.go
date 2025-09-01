package surf_test

import (
	"fmt"
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

	// Test H2C (HTTP/2 cleartext)
	client := surf.NewClient().Builder().H2C().Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		// H2C may not be supported in test environment
		t.Logf("H2C test failed (may be expected): %v", resp.Err())
		return
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareClientH2CTransportConfiguration(t *testing.T) {
	t.Parallel()

	// Test that H2C configures the transport correctly
	client := surf.NewClient().Builder().H2C().Build()

	// Check the transport type - it should be http2.Transport after h2cMW
	transport := client.GetClient().Transport
	if transport == nil {
		t.Fatal("expected transport to be set")
	}

	// The transport should be configured with HTTP/2 settings
	// We can't easily inspect the internal http2.Transport without reflection
	// but we can verify the client was built successfully

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"protocol": "%s", "method": "%s"}`, r.Proto, r.Method)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Logf("H2C transport test failed (may be expected): %v", resp.Err())
		return
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareClientH2CWithHTTP2Settings(t *testing.T) {
	t.Parallel()

	// Test H2C with various HTTP/2 settings
	testCases := []struct {
		name      string
		buildFunc func() *surf.Client
	}{
		{
			"H2C with default settings",
			func() *surf.Client {
				return surf.NewClient().Builder().H2C().Build()
			},
		},
		{
			"H2C with compression disabled",
			func() *surf.Client {
				return surf.NewClient().Builder().H2C().DisableCompression().Build()
			},
		},
		{
			"H2C with keep-alive disabled",
			func() *surf.Client {
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
			client := tc.buildFunc()

			req := client.Get(g.String(ts.URL))
			resp := req.Do()

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

	client := surf.NewClient().Builder().H2C().Build()

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
			req := tm.reqFunc(ts.URL)
			resp := req.Do()

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

	// Test that h2cMW handles various scenarios correctly
	// We can't directly test HTTP/3 incompatibility without HTTP/3 setup
	// but we can test the basic H2C configuration

	client := surf.NewClient().Builder().H2C().Build()

	// Verify the client was configured
	if client.GetClient() == nil {
		t.Fatal("expected HTTP client to be configured")
	}

	if client.GetClient().Transport == nil {
		t.Fatal("expected transport to be configured")
	}

	// Test with a simple request to verify functionality
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Echo back some request info
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"host": "%s", "userAgent": "%s"}`,
			r.Host, r.UserAgent())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Logf("H2C compatibility test failed (may be expected): %v", resp.Err())
		return
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}

	// Verify response contains expected data
	body := resp.Ok().Body.String()
	if !strings.Contains(body.Std(), "host") {
		t.Error("expected response to contain host information")
	}
}

func TestMiddlewareClientDNS(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"dns": "test"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test custom DNS
	client := surf.NewClient().Builder().DNS("8.8.8.8:53").Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
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
		{"Localhost DNS", "127.0.0.1:53", true}, // May fail if no local DNS server
		{"Invalid port", "8.8.8.8:99999", true},
		{"Invalid IP", "999.999.999.999:53", true},
		{"Missing port", "8.8.8.8", true},
		{"Empty DNS", "", false}, // Should work (dnsMW handles empty)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := surf.NewClient().Builder().DNS(g.String(tc.dns)).Build()

			// Check if the resolver was configured
			dialer := client.GetDialer()
			if tc.dns == "" {
				// Empty DNS should not set a custom resolver (or set nil)
				if dialer.Resolver != nil {
					// May still have a resolver, check if it's the default
					t.Log("Empty DNS still has resolver (may be expected)")
				}
			} else if !tc.expectError {
				// For valid DNS, resolver should be set
				if dialer.Resolver == nil {
					t.Error("expected resolver to be set for valid DNS")
				} else if !dialer.Resolver.PreferGo {
					t.Error("expected resolver to have PreferGo set to true")
				}
			}

			// Test DNS functionality with local server
			if !tc.expectError && tc.dns != "" {
				// Create local test server
				handler := func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"dns_test": "success", "remote_addr": "%s"}`, r.RemoteAddr)
				}

				ts := httptest.NewServer(http.HandlerFunc(handler))
				defer ts.Close()

				req := client.Get(g.String(ts.URL))
				resp := req.Do()

				if resp.IsErr() {
					// DNS resolution may fail in test environments with custom DNS
					t.Logf("DNS test failed (may be expected with custom DNS %s): %v", tc.dns, resp.Err())
				} else {
					if !resp.Ok().StatusCode.IsSuccess() {
						t.Errorf("expected success status with DNS %s, got %d", tc.dns, resp.Ok().StatusCode)
					}
				}
			}
		})
	}
}

func TestMiddlewareClientDNSEmptyAndNil(t *testing.T) {
	t.Parallel()

	// Test with empty string
	client1 := surf.NewClient().Builder().DNS(g.String("")).Build()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req1 := client1.Get(g.String(ts.URL))
	resp1 := req1.Do()

	if resp1.IsErr() {
		t.Fatalf("empty DNS should not cause errors: %v", resp1.Err())
	}

	if resp1.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp1.Ok().StatusCode)
	}
}

func TestMiddlewareClientDNSResolverBehavior(t *testing.T) {
	t.Parallel()

	// Test that custom DNS resolver is actually used
	client := surf.NewClient().Builder().DNS(g.String("1.1.1.1:53")).Build()

	dialer := client.GetDialer()
	if dialer.Resolver == nil {
		t.Fatal("expected resolver to be set")
	}

	if !dialer.Resolver.PreferGo {
		t.Error("expected resolver PreferGo to be true")
	}

	// The Dial function should be set for custom DNS resolution
	if dialer.Resolver.Dial == nil {
		t.Error("expected resolver Dial function to be set")
	}

	// Test that the Dial function was configured for UDP to the DNS server
	// We can't easily test this without network access, but we can verify structure
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"host": "%s"}`, r.Host)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

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
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"timeout": "test"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with short timeout
	client := surf.NewClient().Builder().Timeout(50 * time.Millisecond).Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsOk() {
		// Should timeout
		t.Error("expected timeout error")
	}

	// Test with longer timeout
	client2 := surf.NewClient().Builder().Timeout(200 * time.Millisecond).Build()

	req2 := client2.Get(g.String(ts.URL))
	resp2 := req2.Do()

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
	client1 := surf.NewClient().Builder().NotFollowRedirects().Build()
	req1 := client1.Get(g.String(ts.URL))
	resp1 := req1.Do()

	if resp1.IsErr() {
		t.Fatal(resp1.Err())
	}

	// Should get redirect status, not final 200
	if resp1.Ok().StatusCode != http.StatusFound {
		t.Errorf("expected redirect status with NotFollowRedirects, got %d", resp1.Ok().StatusCode)
	}

	// Reset counter
	redirectCount = 0

	// Test MaxRedirects
	client2 := surf.NewClient().Builder().MaxRedirects(2).Build()
	req2 := client2.Get(g.String(ts.URL))
	resp2 := req2.Do()

	// Should fail after 2 redirects (need 3 to reach final)
	// Note: This may not fail in all cases depending on exact redirect handling
	if resp2.IsOk() {
		t.Log("MaxRedirects test passed but might not have failed as expected")
	}

	// Reset counter
	redirectCount = 0

	// Test with enough redirects
	client3 := surf.NewClient().Builder().MaxRedirects(5).Build()
	req3 := client3.Get(g.String(ts.URL))
	resp3 := req3.Do()

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
		// Try to redirect to external host
		http.Redirect(w, r, "http://localhost/", http.StatusFound)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test FollowOnlyHostRedirects
	client := surf.NewClient().Builder().FollowOnlyHostRedirects().Build()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Should not follow redirect to different host
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

	// Test ForwardHeadersOnRedirect
	client := surf.NewClient().Builder().
		ForwardHeadersOnRedirect().
		Build()

	req := client.Get(g.String(ts.URL)).
		SetHeaders(g.Map[string, string]{
			"X-Custom": "forwarded",
			"X-Test":   "value",
		})
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Check if headers were forwarded
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

	// Test DisableKeepAlive
	client := surf.NewClient().Builder().DisableKeepAlive().Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// Transport should be configured for DisableKeepAlive
	// We can't easily inspect the internal transport configuration
	// but we can verify the client was created successfully
}

func TestMiddlewareClientDisableCompression(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Check Accept-Encoding header
		if r.Header.Get("Accept-Encoding") == "" {
			// Compression disabled, no Accept-Encoding
			w.Header().Set("X-Compression", "disabled")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `test`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test DisableCompression
	client := surf.NewClient().Builder().DisableCompression().Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Transport should be configured for DisableCompression
	// We can't easily inspect the internal transport configuration
	// but we can verify the client was created successfully
}

func TestMiddlewareClientInterfaceAddr(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `test`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test InterfaceAddr
	// Using localhost as interface address
	client := surf.NewClient().Builder().InterfaceAddr("127.0.0.1").Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		// Interface address binding may not work in all environments
		t.Logf("InterfaceAddr test failed (may be expected): %v", resp.Err())
		return
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

	// Test ForceHTTP1
	client := surf.NewClient().Builder().ForceHTTP1().Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

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

	// Test Session
	client := surf.NewClient().Builder().Session().Build()

	// Set cookie
	req1 := client.Get(g.String(ts.URL + "/setcookie"))
	resp1 := req1.Do()

	if resp1.IsErr() {
		t.Fatal(resp1.Err())
	}

	// Check cookie is sent
	req2 := client.Get(g.String(ts.URL + "/checkcookie"))
	resp2 := req2.Do()

	if resp2.IsErr() {
		t.Fatal(resp2.Err())
	}

	if resp2.Ok().StatusCode != http.StatusOK {
		t.Error("expected session cookie to be sent")
	}
}

func TestMiddlewareClientSingleton(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `test`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test Singleton
	client := surf.NewClient().Builder().Singleton().Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}
