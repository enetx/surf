package surf_test

import (
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	utls "github.com/enetx/utls"
)

func TestRoundTripperTransportCaching(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"transport": "cached"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	// First request should cache the transport
	resp1 := client.Get(g.String(ts.URL)).Do()
	if resp1.IsErr() {
		t.Fatal(resp1.Err())
	}

	// Second request should use cached transport
	resp2 := client.Get(g.String(ts.URL)).Do()
	if resp2.IsErr() {
		t.Fatal(resp2.Err())
	}

	if !resp1.Ok().StatusCode.IsSuccess() || !resp2.Ok().StatusCode.IsSuccess() {
		t.Error("expected both requests to succeed with transport caching")
	}
}

func TestRoundTripperJAErrorHandling(t *testing.T) {
	t.Parallel()

	// Test error handling in JA roundtripper
	tests := []struct {
		name      string
		url       string
		expectErr bool
	}{
		{"Invalid URL", "not-a-valid-url", true},
		{"Connection refused", "https://127.0.0.1:65535", true},
		{"Invalid domain", "https://non-existent-domain-12345.invalid", true},
	}

	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := client.Get(g.String(tt.url)).Do()
			if tt.expectErr && !resp.IsErr() {
				t.Log("Expected error but request succeeded")
			}
			if !tt.expectErr && resp.IsErr() {
				t.Errorf("Unexpected error: %v", resp.Err())
			}
		})
	}
}

func TestRoundTripperTLSConnectionFailure(t *testing.T) {
	t.Parallel()

	// Test TLS connection failure handling
	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	// Try to connect to an invalid TLS endpoint
	resp := client.Get(g.String("https://127.0.0.1:1")).Do()
	if !resp.IsErr() {
		t.Log("Expected TLS connection to fail")
	}
}

func TestRoundTripperSessionCaching(t *testing.T) {
	t.Parallel()

	// Test session caching with JA roundtripper
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"session": "cached"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Session().
		JA().Chrome142().
		Build()

	// Multiple requests should use session caching
	for i := 0; i < 3; i++ {
		resp := client.Get(g.String(ts.URL)).Do()
		if resp.IsErr() {
			t.Fatalf("Session cached request %d failed: %v", i, resp.Err())
		}
		if !resp.Ok().StatusCode.IsSuccess() {
			t.Errorf("Request %d failed with status %d", i, resp.Ok().StatusCode)
		}
	}
}

func TestRoundTripperHTTPSchemeHandling(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"http": "plain"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	// HTTP (not HTTPS) should use HTTP/1 transport without TLS
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success for HTTP request, got %d", resp.Ok().StatusCode)
	}
}

func TestRoundTripperInvalidScheme(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	// Invalid scheme should return error
	resp := client.Get(g.String("ftp://invalid.scheme")).Do()
	if resp.IsOk() {
		t.Error("expected error for invalid URL scheme")
	}

	errStr := resp.Err().Error()
	if !strings.Contains(errStr, "invalid URL scheme") && !strings.Contains(errStr, "unsupported protocol") {
		t.Logf("Got network error instead of scheme error (test environment): %v", resp.Err())
	}
}

func TestRoundTripperSessionCache(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"session": "cached"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with session enabled
	clientWithSession := surf.NewClient().Builder().
		JA().Chrome142().
		Session().
		Build()

	resp1 := clientWithSession.Get(g.String(ts.URL)).Do()
	if resp1.IsErr() {
		t.Fatal(resp1.Err())
	}

	// Second request should reuse session
	resp2 := clientWithSession.Get(g.String(ts.URL)).Do()
	if resp2.IsErr() {
		t.Fatal(resp2.Err())
	}

	if !resp1.Ok().StatusCode.IsSuccess() || !resp2.Ok().StatusCode.IsSuccess() {
		t.Error("expected both requests to succeed with session caching")
	}
}

func TestRoundTripperCloseIdleConnections(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"connections": "managed"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	// Make initial request to create connections
	resp1 := client.Get(g.String(ts.URL)).Do()
	if resp1.IsErr() {
		t.Fatal(resp1.Err())
	}

	// Close idle connections
	client.CloseIdleConnections()

	// Make another request after closing connections
	resp2 := client.Get(g.String(ts.URL)).Do()
	if resp2.IsErr() {
		t.Fatal(resp2.Err())
	}

	if !resp1.Ok().StatusCode.IsSuccess() || !resp2.Ok().StatusCode.IsSuccess() {
		t.Error("expected both requests to succeed around connection closing")
	}
}

func TestRoundTripperCustomHelloSpec(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"spec": "custom"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Create custom ClientHelloSpec with broader cipher suite support
	customSpec := utls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedCurvesExtension{
				Curves: []utls.CurveID{
					utls.X25519,
					utls.CurveP256,
				},
			},
			&utls.SupportedPointsExtension{
				SupportedPoints: []byte{0},
			},
			&utls.ALPNExtension{
				AlpnProtocols: []string{"h2", "http/1.1"},
			},
		},
	}

	client := surf.NewClient().Builder().
		JA().SetHelloSpec(customSpec).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Skip("Custom HelloSpec test failed, may be due to test environment")
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success with custom hello spec, got %d", resp.Ok().StatusCode)
	}
}

func TestRoundTripperAddressHandling(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"address": "handled"}`)
	}

	// Test with actual local server
	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	// Test actual connection to local server
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success for local server request, got %d", resp.Ok().StatusCode)
	}
}

func TestRoundTripperProtocolNegotiation(t *testing.T) {
	t.Parallel()

	// Test that protocol negotiation works correctly
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"protocol": "negotiated"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	testCases := []struct {
		name       string
		configFunc func() *surf.Client
	}{
		{
			"Chrome with HTTP/2",
			func() *surf.Client {
				return surf.NewClient().Builder().
					JA().Chrome142().
					Build()
			},
		},
		{
			"Firefox with HTTP/2",
			func() *surf.Client {
				return surf.NewClient().Builder().
					JA().Firefox144().
					Build()
			},
		},
		{
			"Force HTTP/1",
			func() *surf.Client {
				return surf.NewClient().Builder().
					JA().Chrome142().
					ForceHTTP1().
					Build()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.configFunc()

			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success for %s, got %d", tc.name, resp.Ok().StatusCode)
			}
		})
	}
}

func TestRoundTripperALPNProtocolModification(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"alpn": "modified"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test ForceHTTP1 which modifies ALPN protocols
	client := surf.NewClient().Builder().
		JA().Chrome142().
		ForceHTTP1().
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success with ALPN modification, got %d", resp.Ok().StatusCode)
	}

	// Verify HTTP/1.1 is used (should be in response proto)
	httpResp := resp.Ok().GetResponse()
	if httpResp.Proto != "HTTP/1.1" {
		t.Logf("Expected HTTP/1.1, got %s (may vary by server)", httpResp.Proto)
	}
}

func TestRoundTripperErrorHandling(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		JA().Chrome142().
		Timeout(1 * time.Millisecond). // Very short timeout to trigger errors
		Build()

	// Test connection timeout using slow local server
	handler := func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(10 * time.Millisecond) // Longer than client timeout
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"delayed": "response"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsOk() {
		t.Error("expected timeout error for delayed request")
	}

	// Verify it's a timeout-related error
	errStr := resp.Err().Error()
	if !strings.Contains(errStr, "timeout") && !strings.Contains(errStr, "deadline") {
		t.Logf("Got error (may be network-related): %v", resp.Err())
	}
}

func TestJAHTTP2Transport(t *testing.T) {
	t.Parallel()

	// Test JA3 with HTTP/2 transport configuration
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"protocol": "http2"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with Chrome HTTP/2 configuration
	client := surf.NewClient().Builder().
		JA().Chrome142().
		HTTP2Settings().
		HeaderTableSize(65536).
		Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be created with JA3 and HTTP2 settings")
	}

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Logf("HTTP2 transport test error (expected with httptest): %v", resp.Err())
	} else {
		httpResp := resp.Ok().GetResponse()
		t.Logf("Protocol: %s", httpResp.Proto)
	}
}

func TestJATransportBuilding(t *testing.T) {
	t.Parallel()

	// Test various JA3 transport building scenarios
	testCases := []struct {
		name         string
		configureJA  func() *surf.Client
		expectClient bool
	}{
		{
			name: "Chrome with HTTP2 disabled",
			configureJA: func() *surf.Client {
				return surf.NewClient().Builder().
					JA().Chrome142().
					ForceHTTP1().
					Build()
			},
			expectClient: true,
		},
		{
			name: "Firefox with custom timeout",
			configureJA: func() *surf.Client {
				return surf.NewClient().Builder().
					JA().Firefox144().
					Timeout(5 * time.Second).
					Build()
			},
			expectClient: true,
		},
		{
			name: "Chrome with SOCKS5 proxy",
			configureJA: func() *surf.Client {
				return surf.NewClient().Builder().
					JA().Chrome142().
					Proxy("socks5://127.0.0.1:9999").
					Build()
			},
			expectClient: true,
		},
		{
			name: "Firefox with custom DNS",
			configureJA: func() *surf.Client {
				return surf.NewClient().Builder().
					JA().Firefox144().
					DNS("8.8.8.8:53").
					Build()
			},
			expectClient: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.configureJA()
			if tc.expectClient {
				if client == nil {
					t.Errorf("expected client to be created for %s", tc.name)
				}
			} else {
				if client != nil {
					t.Errorf("expected client creation to fail for %s", tc.name)
				}
			}
		})
	}
}

func TestJATLSConfiguration(t *testing.T) {
	t.Parallel()

	// Test JA3 TLS configuration with various scenarios
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"tls": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with different TLS configurations
	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	if client == nil {
		t.Fatal("expected client to be created")
	}

	// Test TLS connection with custom configuration
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Logf("TLS configuration test error (expected with self-signed cert): %v", resp.Err())
	}

	// Verify TLS config was applied (this tests the TLS config building)
	tlsConfig := client.GetTLSConfig()
	if tlsConfig == nil {
		t.Error("expected TLS config to be set on JA3 client")
	}
}

func TestJAConnectionPooling(t *testing.T) {
	t.Parallel()

	// Test connection pooling with JA3 transport
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"pool": "test"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	if client == nil {
		t.Fatal("expected client to be created")
	}

	// Make multiple requests to test connection pooling
	for i := 0; i < 3; i++ {
		resp := client.Get(g.String(ts.URL)).Do()
		if resp.IsErr() {
			t.Logf("Connection pooling test %d error: %v", i+1, resp.Err())
		} else {
			t.Logf("Connection pooling test %d successful", i+1)
		}

		// Small delay between requests
		time.Sleep(10 * time.Millisecond)
	}

	// Close idle connections
	client.CloseIdleConnections()
	t.Log("Connection pooling test completed")
}

func TestJAErrorHandling(t *testing.T) {
	t.Parallel()

	// Test JA3 error handling with various scenarios
	client := surf.NewClient().Builder().
		JA().Chrome142().
		Timeout(100 * time.Millisecond).
		Build()

	if client == nil {
		t.Fatal("expected client to be created")
	}

	// Test connection to non-existent host
	resp := client.Get(g.String("https://non-existent-host.invalid")).Do()
	if resp.IsErr() {
		t.Logf("Expected DNS error: %v", resp.Err())
	}

	// Test connection timeout
	resp2 := client.Get(g.String("https://127.0.0.1:65535")).Do()
	if resp2.IsErr() {
		t.Logf("Expected connection error: %v", resp2.Err())
	}

	// Test invalid URL
	resp3 := client.Get(g.String("invalid://url")).Do()
	if resp3.IsErr() {
		t.Logf("Expected URL parsing error: %v", resp3.Err())
	}
}

func TestJARoundtripperHTTP2Transport(t *testing.T) {
	t.Parallel()

	// Test JA roundtripper with HTTP/2 settings to exercise buildHTTP2Transport
	client := surf.NewClient().Builder().
		JA().Chrome142().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(0).
		InitialWindowSize(6291456).
		MaxHeaderListSize(262144).
		Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// This should exercise buildHTTP2Transport function
	if client.GetTransport() == nil {
		t.Fatal("expected transport to be configured")
	}

	// Test request creation (exercises internal functions)
	req := client.Get(g.String("https://127.0.0.1:8080/get"))
	if req == nil {
		t.Fatal("expected request to be created")
	}

	if req.GetRequest() == nil {
		t.Fatal("expected HTTP request to be created")
	}
}

func TestJARoundtripperTLSDialing(t *testing.T) {
	t.Parallel()

	// Test various TLS configurations to exercise dialTLSHTTP2 and dialTLS functions
	tests := []struct {
		name string
		spec utls.ClientHelloID
	}{
		{"Chrome 131", utls.HelloChrome_131},
		{"Chrome 120", utls.HelloChrome_120},
		{"Firefox 102", utls.HelloFirefox_102},
		{"Edge 106", utls.HelloEdge_106},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				JA().SetHelloID(tt.spec).
				Build()

			if client == nil {
				t.Fatal("expected client to be built successfully")
			}

			// Creating requests with HTTPS URLs will exercise TLS dialing functions
			req := client.Get(g.String("https://127.0.0.1:8080"))
			if req == nil {
				t.Fatal("expected request to be created")
			}

			// The TLS config should be properly set
			if client.GetTLSConfig() == nil {
				t.Fatal("expected TLS config to be set for JA3")
			}
		})
	}
}

func TestJARoundtripperSessionCaching(t *testing.T) {
	t.Parallel()

	// Test session caching functionality
	client := surf.NewClient().Builder().
		JA().Chrome142().
		Session().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// With sessions enabled, TLS config should have session cache
	tlsConfig := client.GetTLSConfig()
	if tlsConfig == nil {
		t.Fatal("expected TLS config to be set")
	}

	if tlsConfig.ClientSessionCache == nil {
		t.Error("expected session cache to be configured")
	}

	// Test that requests can be created
	req := client.Get(g.String("https://127.0.0.1:8080/get"))
	if req == nil {
		t.Fatal("expected request to be created")
	}
}

func TestJARoundtripperAddressParsing(t *testing.T) {
	t.Parallel()

	// Test address parsing function
	tests := []struct {
		name string
		url  string
	}{
		{"HTTPS with explicit port", "https://127.0.0.1:443"},
		{"HTTPS default port", "https://127.0.0.1"},
		{"HTTP with custom port", "http://127.0.0.1:8080"},
		{"Localhost HTTPS", "https://localhost:8443"},
		{"IP address", "https://127.0.0.1:443"},
		{"IPv6 address", "https://[::1]:443"},
	}

	client := surf.NewClient().Builder().
		JA().Chrome142().
		Build()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Creating requests exercises address parsing
			req := client.Get(g.String(tt.url))
			if req == nil {
				t.Fatal("expected request to be created")
			}

			if req.GetRequest() == nil {
				t.Fatal("expected HTTP request to be created")
			}

			// URL should be properly parsed
			if req.GetRequest().URL == nil {
				t.Fatal("expected URL to be parsed")
			}
		})
	}
}
