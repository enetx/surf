package surf_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestBuilderBuild(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()
	originalClient := client

	builder := client.Builder()
	if builder == nil {
		t.Fatal("Builder() returned nil")
	}

	built := builder.Build()
	if built != originalClient {
		t.Error("Build() should return the same client instance")
	}
}

func TestBuilderWith(t *testing.T) {
	t.Parallel()

	var clientMWCalled bool
	var requestMWCalled bool
	var responseMWCalled bool

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		With(func(*surf.Client) error {
			clientMWCalled = true
			return nil
		}).
		With(func(*surf.Request) error {
			requestMWCalled = true
			return nil
		}).
		With(func(*surf.Response) error {
			responseMWCalled = true
			return nil
		}).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !clientMWCalled {
		t.Error("client middleware was not called")
	}
	if !requestMWCalled {
		t.Error("request middleware was not called")
	}
	if !responseMWCalled {
		t.Error("response middleware was not called")
	}
}

func TestBuilderWithPriority(t *testing.T) {
	t.Parallel()

	var executionOrder []int

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		With(func(*surf.Request) error {
			executionOrder = append(executionOrder, 3)
			return nil
		}, 3).
		With(func(*surf.Request) error {
			executionOrder = append(executionOrder, 1)
			return nil
		}, 1).
		With(func(*surf.Request) error {
			executionOrder = append(executionOrder, 2)
			return nil
		}, 2).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Should execute in priority order: 1, 2, 3
	expected := []int{1, 2, 3}
	if len(executionOrder) != len(expected) {
		t.Fatalf("expected %d middleware calls, got %d", len(expected), len(executionOrder))
	}

	for i, exp := range expected {
		if executionOrder[i] != exp {
			t.Errorf("expected middleware order %v, got %v", expected, executionOrder)
			break
		}
	}
}

func TestBuilderWithInvalidType(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid middleware type")
		}
	}()

	surf.NewClient().Builder().
		With("invalid type").
		Build()
}

func TestBuilderSingleton(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Singleton().
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test CloseIdleConnections works with singleton
	client.CloseIdleConnections()
}

func TestBuilderH2C(t *testing.T) {
	t.Parallel()

	// H2C requires special server setup, just test that method doesn't panic
	client := surf.NewClient().Builder().
		H2C().
		Build()

	if client == nil {
		t.Error("H2C builder returned nil client")
	}
}

func TestBuilderHTTP2Settings(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(0).
		MaxConcurrentStreams(1000).
		InitialWindowSize(6291456).
		MaxFrameSize(16384).
		MaxHeaderListSize(262144).
		ConnectionFlow(15663105).
		Set().
		Build()

	if client == nil {
		t.Error("HTTP2Settings builder returned nil client")
	}
}

func TestBuilderImpersonate(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Singleton(). // Required for impersonate
		Impersonate().
		Chrome().
		Build()

	if client == nil {
		t.Error("Impersonate builder returned nil client")
	}

	defer client.CloseIdleConnections()
}

func TestBuilderJA3(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Singleton(). // Required for JA
		JA().
		Chrome().
		Build()

	if client == nil {
		t.Error("JA3 builder returned nil client")
	}

	defer client.CloseIdleConnections()
}

func TestBuilderUnixDomainSocket(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		UnixSocket("/tmp/test.sock").
		Build()

	if client == nil {
		t.Error("UnixDomainSocket builder returned nil client")
	}
}

func TestBuilderDNS(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		DNS("8.8.8.8:53").
		Build()

	if client == nil {
		t.Error("DNS builder returned nil client")
	}
}

func TestBuilderDNSOverTLS(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		DNSOverTLS().
		Cloudflare().
		Build()

	if client == nil {
		t.Error("DNSOverTLS builder returned nil client")
	}
}

func TestBuilderTimeout(t *testing.T) {
	t.Parallel()

	timeout := 30 * time.Second

	client := surf.NewClient().Builder().
		Timeout(timeout).
		Build()

	if client.GetClient().Timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, client.GetClient().Timeout)
	}
}

func TestBuilderInterfaceAddr(t *testing.T) {
	t.Parallel()

	// Use localhost as a valid interface address
	client := surf.NewClient().Builder().
		InterfaceAddr("127.0.0.1").
		Build()

	if client == nil {
		t.Error("InterfaceAddr builder returned nil client")
	}

	// Check that dialer has local address set
	dialer := client.GetDialer()
	if dialer.LocalAddr == nil {
		t.Error("expected LocalAddr to be set")
	}

	addr, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok {
		t.Errorf("expected TCPAddr, got %T", dialer.LocalAddr)
	}

	if addr.IP.String() != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", addr.IP.String())
	}
}

func TestBuilderProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		proxy any
	}{
		{"string proxy", "http://localhost:8080"},
		{"g.String proxy", g.String("http://localhost:8080")},
		{"slice proxy", []string{"http://localhost:8081", "http://localhost:8082"}},
		{"g.Slice proxy", g.SliceOf("http://localhost:8081", "http://localhost:8082")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				Proxy(tt.proxy).
				Build()

			if client == nil {
				t.Error("Proxy builder returned nil client")
			}
		})
	}
}

func TestBuilderAuth(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Error("expected Authorization header")
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	t.Run("BasicAuth", func(t *testing.T) {
		client := surf.NewClient().Builder().
			BasicAuth("user:pass").
			Build()

		resp := client.Get(g.String(ts.URL)).Do()
		if resp.IsErr() {
			t.Fatal(resp.Err())
		}
	})

	t.Run("BearerAuth", func(t *testing.T) {
		client := surf.NewClient().Builder().
			BearerAuth("token123").
			Build()

		resp := client.Get(g.String(ts.URL)).Do()
		if resp.IsErr() {
			t.Fatal(resp.Err())
		}
	})
}

func TestBuilderUserAgent(t *testing.T) {
	t.Parallel()

	customUA := "CustomAgent/1.0"

	handler := func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != customUA {
			t.Errorf("expected User-Agent %s, got %s", customUA, ua)
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		UserAgent(customUA).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}
}

func TestBuilderHeaders(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "value1" {
			t.Error("missing X-Custom header from SetHeaders")
		}
		if r.Header.Get("X-Added") != "value2" {
			t.Error("missing X-Added header from AddHeaders")
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		SetHeaders("X-Custom", "value1").
		AddHeaders("X-Added", "value2").
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}
}

func TestBuilderCookies(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("test")
		if err != nil || cookie.Value != "value" {
			t.Errorf("expected test=value cookie, got %v", cookie)
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		AddCookies(&http.Cookie{Name: "test", Value: "value"}).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}
}

func TestBuilderWithContext(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Just check that context is not nil and was set
		if r.Context() == context.Background() {
			t.Error("expected custom context")
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		WithContext(ctx).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}
}

func TestBuilderContentType(t *testing.T) {
	t.Parallel()

	contentType := "application/custom"

	handler := func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if ct != contentType {
			t.Errorf("expected Content-Type %s, got %s", contentType, ct)
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		ContentType(g.String(contentType)).
		Build()

	resp := client.Post(g.String(ts.URL), "data").Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}
}

func TestBuilderCacheBody(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "cached content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		CacheBody().
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// First read
	content1 := resp.Ok().Body.String()
	if content1 != "cached content" {
		t.Errorf("expected 'cached content', got %s", content1)
	}

	// Second read should return cached content
	content2 := resp.Ok().Body.String()
	if content2 != "cached content" {
		t.Error("expected cached content on second read")
	}
}

func TestBuilderGetRemoteAddress(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		GetRemoteAddress().
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().RemoteAddress() == nil {
		t.Error("expected remote address to be captured")
	}
}

func TestBuilderDisableKeepAlive(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		DisableKeepAlive().
		Build()

	transport := client.GetTransport().(*http.Transport)
	if !transport.DisableKeepAlives {
		t.Error("expected DisableKeepAlives to be true")
	}
}

func TestBuilderDisableCompression(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		DisableCompression().
		Build()

	transport := client.GetTransport().(*http.Transport)
	if !transport.DisableCompression {
		t.Error("expected DisableCompression to be true")
	}
}

func TestBuilderRetry(t *testing.T) {
	t.Parallel()

	attemptCount := 0
	handler := func(w http.ResponseWriter, _ *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "success")
		}
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Retry(5, 10*time.Millisecond).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().Attempts != 2 {
		t.Errorf("expected 2 retry attempts, got %d", resp.Ok().Attempts)
	}

	if !resp.Ok().Body.Contains("success") {
		t.Error("expected 'success' in body")
	}
}

func TestBuilderRetryWithCustomCodes(t *testing.T) {
	t.Parallel()

	attemptCount := 0
	handler := func(w http.ResponseWriter, _ *http.Request) {
		attemptCount++
		if attemptCount < 2 {
			w.WriteHeader(http.StatusBadRequest) // 400 - should retry
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "success")
		}
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Retry(3, 10*time.Millisecond, http.StatusBadRequest). // Custom retry code
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().Attempts != 1 {
		t.Errorf("expected 1 retry attempt, got %d", resp.Ok().Attempts)
	}
}

func TestBuilderForceHTTP1(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		ForceHTTP1().
		Build()

	if client == nil {
		t.Error("ForceHTTP1 builder returned nil client")
	}
}

func TestBuilderForceHTTP2(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		ForceHTTP2().
		Build()

	if client == nil {
		t.Error("ForceHTTP2 builder returned nil client")
	}
}

func TestBuilderSession(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Session().
		Build()

	if client.GetClient().Jar == nil {
		t.Error("expected cookie jar to be set for session")
	}

	if client.GetTLSConfig().ClientSessionCache == nil {
		t.Error("expected TLS client session cache to be set")
	}
}

func TestBuilderRedirects(t *testing.T) {
	t.Parallel()

	redirectCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		if redirectCount == 0 {
			redirectCount++
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "final")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	t.Run("MaxRedirects", func(t *testing.T) {
		client := surf.NewClient().Builder().
			MaxRedirects(1).
			Build()

		resp := client.Get(g.String(ts.URL)).Do()
		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		if !resp.Ok().Body.Contains("final") {
			t.Error("expected redirect to be followed")
		}
	})

	t.Run("NotFollowRedirects", func(t *testing.T) {
		redirectCount = 0 // Reset counter
		client := surf.NewClient().Builder().
			NotFollowRedirects().
			Build()

		resp := client.Get(g.String(ts.URL)).Do()
		if resp.IsErr() {
			t.Fatal(resp.Err())
		}

		if resp.Ok().StatusCode != 302 {
			t.Errorf("expected status 302, got %d", resp.Ok().StatusCode)
		}
	})

	t.Run("FollowOnlyHostRedirects", func(t *testing.T) {
		client := surf.NewClient().Builder().
			FollowOnlyHostRedirects().
			Build()

		if client == nil {
			t.Error("FollowOnlyHostRedirects builder returned nil client")
		}
	})

	t.Run("ForwardHeadersOnRedirect", func(t *testing.T) {
		client := surf.NewClient().Builder().
			ForwardHeadersOnRedirect().
			Build()

		if client == nil {
			t.Error("ForwardHeadersOnRedirect builder returned nil client")
		}
	})
}

func TestBuilderRedirectPolicy(t *testing.T) {
	t.Parallel()

	redirectCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		if redirectCount == 0 {
			redirectCount++
			http.Redirect(w, r, "/redirect", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Custom redirect policy that stops all redirects
	client := surf.NewClient().Builder().
		RedirectPolicy(func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Should get the redirect response, not follow it
	if resp.Ok().StatusCode != 302 {
		t.Errorf("expected status 302, got %d", resp.Ok().StatusCode)
	}
}

func TestBuilderBoundary(t *testing.T) {
	t.Parallel()

	expectedBoundary := "test-boundary-123"

	handler := func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if contentType != "" && !g.String(contentType).Contains(g.String(expectedBoundary)) {
			t.Errorf("expected boundary %s in content-type, got %s", expectedBoundary, contentType)
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Boundary(func() g.String { return g.String(expectedBoundary) }).
		Build()

	// Test with multipart
	data := g.NewMapOrd[g.String, g.String](1)
	data.Set("field", "value")

	resp := client.Multipart(g.String(ts.URL), data).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}
}

func TestBuilderString(t *testing.T) {
	t.Parallel()

	builder := surf.NewClient().Builder().
		Timeout(30 * time.Second).
		UserAgent("Test/1.0")

	str := builder.String()
	if str == "" {
		t.Error("expected non-empty string representation")
	}

	// String should contain type information
	if !g.String(str).Contains("Builder") {
		t.Error("expected 'builder' in string representation")
	}
}
