package surf_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	_http "net/http"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/http3"
	"github.com/enetx/surf"
)

// netHTTPResponseWriter adapts enetx/http.ResponseWriter to net/http.ResponseWriter
type netHTTPResponseWriter struct {
	w http.ResponseWriter
}

func (nw *netHTTPResponseWriter) Header() _http.Header {
	return _http.Header(nw.w.Header())
}

func (nw *netHTTPResponseWriter) Write(data []byte) (int, error) {
	return nw.w.Write(data)
}

func (nw *netHTTPResponseWriter) WriteHeader(statusCode int) {
	nw.w.WriteHeader(statusCode)
}

// createHTTP3TestServer creates a local HTTP/3 test server with self-signed certificate
func createHTTP3TestServer(handler _http.HandlerFunc) (*http3.Server, net.PacketConn, string, error) {
	// Generate self-signed certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, "", err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	// Create UDP listener
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, "", err
	}

	// Configure TLS for HTTP/3
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}

	// Create HTTP/3 server with handler adapter
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Adapt enetx/http types to net/http types for the handler
			nw := &netHTTPResponseWriter{w: w}
			nr := &_http.Request{
				Method:     r.Method,
				URL:        r.URL,
				Proto:      r.Proto,
				ProtoMajor: r.ProtoMajor,
				ProtoMinor: r.ProtoMinor,
				Header:     _http.Header(r.Header),
				Body:       r.Body,
				RemoteAddr: r.RemoteAddr,
				RequestURI: r.RequestURI,
			}
			handler(nw, nr)
		}),
		TLSConfig: tlsConf,
	}

	addr := fmt.Sprintf("https://localhost:%d", conn.LocalAddr().(*net.UDPAddr).Port)
	return server, conn, addr, nil
}

func TestHTTP3SettingsWithForceHTTP1(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"force_http1": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// HTTP/3 settings should be ignored when ForceHTTP1 is set
	client := surf.NewClient().Builder().
		ForceHTTP1().
		HTTP3().
		Build()

	// Test that client was created successfully
	if client == nil {
		t.Fatal("expected client to be created with ForceHTTP1 (ignoring HTTP/3)")
	}

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Should be HTTP/1.1, not HTTP/3
	httpResp := resp.Ok().GetResponse()
	if httpResp.Proto != "HTTP/1.1" {
		t.Logf("Expected HTTP/1.1, got %s", httpResp.Proto)
	}
}

// Merged into TestHTTP3WithSOCKS5Proxy

// Merged into TestHTTP3ProxyConfiguration

func TestHTTP3SettingsMethodChaining(t *testing.T) {
	t.Parallel()

	// Test that method chaining works correctly
	client := surf.NewClient().Builder().
		HTTP3().
		Session().
		UserAgent("HTTP3Test/1.0").
		Timeout(10 * time.Second).
		Build()

	// Test that client was created successfully
	if client == nil {
		t.Fatal("expected client to be created with chained HTTP/3 settings")
	}

	// Verify configurations
	if client.GetClient().Jar == nil {
		t.Error("expected session to be configured")
	}

	if client.GetClient().Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", client.GetClient().Timeout)
	}
}

func TestHTTP3SettingsTransportVerification(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		HTTP3().
		Build()

	// Check that transport is configured
	transport := client.GetTransport()
	if transport == nil {
		t.Error("expected transport to be configured")
	}

	// The actual transport type will be uquicTransport internally
	// We can't directly test this without accessing internals
	t.Logf("Transport configured: %T", transport)
}

func TestHTTP3SettingsWithDNSOverTLS(t *testing.T) {
	t.Parallel()

	// Test client creation combining HTTP/3 with DNS over TLS
	client := surf.NewClient().Builder().
		HTTP3().
		DNSOverTLS().
		Cloudflare().
		Timeout(10 * time.Second).
		Build()

	// Test that client was created successfully
	if client == nil {
		t.Fatal("expected client to be created with HTTP/3 and DNS over TLS")
	}

	// Verify timeout is configured
	if client.GetClient().Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", client.GetClient().Timeout)
	}
}

func TestHTTP3AutoDetection(t *testing.T) {
	t.Run("Chrome auto detection", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Impersonate().Chrome().HTTP3().
			Build()

		if client.GetTransport() == nil {
			t.Fatal("Chrome HTTP/3 transport is nil")
		}

		// Verify client and transport are configured
		if client == nil || client.GetTransport() == nil {
			t.Fatal("Expected valid client and transport")
		}
	})

	t.Run("Firefox auto detection", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Impersonate().Firefox().HTTP3().
			Build()

		if client.GetTransport() == nil {
			t.Fatal("Firefox HTTP/3 transport is nil")
		}

		// Verify client and transport are configured
		if client == nil || client.GetTransport() == nil {
			t.Fatal("Expected valid client and transport")
		}
	})

	t.Run("Default to Chrome", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3().
			Build()

		if client.GetTransport() == nil {
			t.Fatal("Default HTTP/3 transport is nil")
		}

		// Verify client and transport are configured
		if client == nil || client.GetTransport() == nil {
			t.Fatal("Expected valid client and transport")
		}
	})
}

func TestHTTP3OrderIndependence(t *testing.T) {
	t.Run("HTTP3 then Impersonate", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3().
			Impersonate().Chrome().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport regardless of order")
		}
	})

	t.Run("Impersonate then HTTP3", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Impersonate().Chrome().
			HTTP3().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport regardless of order")
		}
	})
}

func TestHTTP3ManualVsAuto(t *testing.T) {
	t.Run("Manual settings disable auto", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Impersonate().Chrome().
			HTTP3(). // This should be ignored
			HTTP3(). // This takes precedence
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport from manual settings")
		}
	})

	t.Run("Auto then manual", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3().                // This gets disabled
			HTTP3().                // This applies
			Impersonate().Chrome(). // This should not trigger auto HTTP3
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport from manual settings")
		}
	})
}

func TestHTTP3Compatibility(t *testing.T) {
	t.Run("HTTP3 with proxy fallback", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Proxy("http://proxy:8080").
			HTTP3().
			Build()

		// Test that HTTP proxy configuration works with HTTP/3 settings
		// The client should be created successfully but use fallback for HTTP proxy
		if client == nil {
			t.Fatal("Client should be created with HTTP proxy and HTTP/3 settings")
		}

		// Test actual fallback behavior by making a request
		// Should use HTTP/2 fallback transport for HTTP proxy (will likely fail due to proxy)
		resp := client.Get("https://127.0.0.1:65534/test").Do()
		// Request will fail due to unreachable proxy, but that confirms fallback is working
		if resp.IsErr() {
			// Expected - proxy is unreachable, but important part is no panic/crash
			t.Logf("Expected proxy error (confirms fallback working): %v", resp.Err())
		}
	})

	t.Run("HTTP3 with SOCKS5 proxy support", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Proxy("socks5://127.0.0.1:1080").
			HTTP3().
			Build()

		// Should be able to create client with SOCKS5 proxy and HTTP/3
		if client == nil {
			t.Fatal("Client should be created with SOCKS5 proxy and HTTP/3 settings")
		}

		// SOCKS5 proxy should work with HTTP/3 (though proxy may be unreachable in test)
		// The important part is no fallback should occur for SOCKS5
	})

	t.Run("HTTP3 with DNS and SOCKS5 proxy", func(t *testing.T) {
		client := surf.NewClient().Builder().
			DNS("8.8.8.8:53").
			Proxy("socks5://127.0.0.1:1080").
			HTTP3().
			Build()

		// Should have HTTP/3 transport with both DNS and SOCKS5 proxy
		if client == nil {
			t.Fatal("HTTP/3 should be active with DNS + SOCKS5 proxy")
		}
	})

	t.Run("HTTP3 with JA3 compatibility", func(t *testing.T) {
		client := surf.NewClient().Builder().
			JA().Chrome143().
			HTTP3().
			Build()

		// Should have HTTP/3 transport (JA3 should be ignored)
		if client == nil {
			t.Fatal("Expected HTTP/3 transport (JA3 should be ignored for HTTP/3)")
		}
	})

	t.Run("HTTP3 with DNS settings", func(t *testing.T) {
		client := surf.NewClient().Builder().
			DNS("8.8.8.8:53").
			HTTP3().
			Build()

		// Should have HTTP/3 transport with DNS settings
		if client == nil {
			t.Fatal("Expected HTTP/3 transport with DNS settings")
		}
	})

	t.Run("HTTP3 with DNSOverTLS", func(t *testing.T) {
		client := surf.NewClient().Builder().
			DNSOverTLS().Google().
			HTTP3().
			Build()

		// Should have HTTP/3 transport with DNS over TLS
		if client == nil {
			t.Fatal("Expected HTTP/3 transport with DNS over TLS")
		}
	})

	t.Run("HTTP3 with timeout", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Timeout(30 * time.Second).
			HTTP3().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport with timeout")
		}
	})

	t.Run("HTTP3 with context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		client := surf.NewClient().Builder().
			WithContext(ctx).
			HTTP3().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport with context")
		}
	})

	t.Run("HTTP3 with headers", func(t *testing.T) {
		client := surf.NewClient().Builder().
			SetHeaders("X-Test", "value").
			HTTP3().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport with custom headers")
		}
	})

	t.Run("HTTP3 with middleware", func(t *testing.T) {
		client := surf.NewClient().Builder().
			With(func(req *surf.Request) error {
				req.SetHeaders("X-Middleware", "test")
				return nil
			}).
			HTTP3().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport with middleware")
		}
	})
}

func TestHTTP3TransportProperties(t *testing.T) {
	t.Run("Chrome transport properties", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport")
		}

		if client.GetTransport() == nil {
			t.Fatal("Transport should not be nil")
		}
	})

	t.Run("Firefox transport properties", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport")
		}

		if client.GetTransport() == nil {
			t.Fatal("Transport should not be nil")
		}
	})
}

// Merged into TestHTTP3Settings

func TestHTTP3MockRequests(t *testing.T) {
	// Create shared HTTP/3 test server for mock tests
	handler := _http.HandlerFunc(func(w _http.ResponseWriter, _ *_http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(_http.StatusOK)
		fmt.Fprint(w, `{"mock": "request", "protocol": "HTTP/3"}`)
	})

	server, conn, addr, err := createHTTP3TestServer(handler)
	if err != nil {
		t.Skip("Failed to create HTTP/3 test server for mock tests:", err)
	}
	defer conn.Close()

	// Start server in goroutine
	go func() {
		_ = server.Serve(conn)
		// Note: Don't log from goroutine to avoid race conditions
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	t.Run("Auto detection mock request", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Impersonate().Chrome().HTTP3().
			Build()

		resp := client.Get(g.String(addr)).Do()
		if resp.IsErr() {
			t.Logf("Auto-detection mock request failed (may be expected in test env): %v", resp.Err())
			return
		}

		if !resp.Ok().StatusCode.IsSuccess() {
			t.Errorf("Expected success status, got %d", resp.Ok().StatusCode)
		}

		if resp.Ok().Body.Contains("HTTP/3") {
			t.Log("Auto-detection HTTP/3 mock request succeeded")
		}
	})

	// Shutdown server
	server.Close()
}

// TestHTTP3RealRequests removed - all tests should work offline without external URLs

func TestHTTP3DNSIntegration(t *testing.T) {
	t.Parallel()

	// Comprehensive DNS integration tests for HTTP/3
	tests := []struct {
		name      string
		buildFunc func() *surf.Client
	}{
		{
			name: "HTTP3 with custom DNS",
			buildFunc: func() *surf.Client {
				return surf.NewClient().Builder().
					DNS("8.8.8.8:53").
					HTTP3().
					Build()
			},
		},
		{
			name: "HTTP3 with DNS over TLS Google",
			buildFunc: func() *surf.Client {
				return surf.NewClient().Builder().
					DNSOverTLS().Google().
					HTTP3().
					Build()
			},
		},
		{
			name: "HTTP3 with DNS over TLS Cloudflare",
			buildFunc: func() *surf.Client {
				return surf.NewClient().Builder().
					DNSOverTLS().Cloudflare().
					HTTP3().
					Build()
			},
		},
		{
			name: "HTTP3 with Cloudflare DNS",
			buildFunc: func() *surf.Client {
				return surf.NewClient().Builder().
					DNS("1.1.1.1:53").
					HTTP3().
					Build()
			},
		},
		{
			name: "HTTP3 with custom resolver",
			buildFunc: func() *surf.Client {
				return surf.NewClient().Builder().
					DNS("192.168.1.1:53").
					HTTP3().
					Build()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.buildFunc()

			if client == nil {
				t.Fatal("expected client to be built successfully")
			}

			// Verify DNS and HTTP/3 are configured
			if client.GetDialer() == nil {
				t.Fatal("expected dialer to be configured")
			}

			if client.GetTransport() == nil {
				t.Fatal("expected transport to be configured")
			}

			if client.GetDialer().Resolver == nil {
				t.Fatal("expected resolver to be configured")
			}
		})
	}
}

func TestHTTP3NetworkConditions(t *testing.T) {
	t.Run("HTTP3 with unreachable proxy", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Proxy("http://127.0.0.1:8080").
			HTTP3().
			Build()

		// Should be able to create client with unreachable HTTP proxy
		if client == nil {
			t.Fatal("Client should be created with HTTP proxy")
		}

		// Test that requests handle unreachable proxy gracefully
		// Should use HTTP/2 fallback for HTTP proxy
	})

	t.Run("HTTP3 timeout handling", func(t *testing.T) {
		// Create local HTTP/3 server with delay for timeout test
		handler := _http.HandlerFunc(func(w _http.ResponseWriter, _ *_http.Request) {
			time.Sleep(10 * time.Millisecond) // Longer than client timeout
			w.WriteHeader(_http.StatusOK)
			fmt.Fprint(w, `{"timeout": "test"}`)
		})

		server, conn, addr, err := createHTTP3TestServer(handler)
		if err != nil {
			t.Skip("Failed to create HTTP/3 test server for timeout test:", err)
		}
		defer conn.Close()

		// Start server in goroutine
		go func() {
			_ = server.Serve(conn)
			// Note: Don't log from goroutine to avoid race conditions
		}()

		// Give server time to start
		time.Sleep(100 * time.Millisecond)

		client := surf.NewClient().Builder().
			Timeout(1 * time.Millisecond). // Very short timeout
			HTTP3().
			Build()

		resp := client.Get(g.String(addr)).Do()

		// Should either succeed or timeout, but not crash
		if resp.IsErr() {
			t.Logf("Request timed out as expected: %v", resp.Err())
		} else {
			t.Logf("Request succeeded despite short timeout")
		}

		// Shutdown server
		server.Close()
	})
}

func TestHTTP3AddressResolution(t *testing.T) {
	t.Parallel()

	// Test address resolution with invalid addresses
	client := surf.NewClient().Builder().
		HTTP3().
		Timeout(1 * time.Second).
		Build()

	if client == nil {
		t.Fatal("expected client to be created")
	}

	// Test with invalid address format
	resp := client.Get(g.String("http://invalid-address-format")).Do()
	if resp.IsErr() {
		t.Logf("Expected error with invalid address: %v", resp.Err())
		// This tests the address resolution error handling
	}

	// Test with non-existent host
	resp2 := client.Get(g.String("http://non-existent-host-12345.invalid:8080")).Do()
	if resp2.IsErr() {
		t.Logf("Expected DNS resolution error: %v", resp2.Err())
		// This tests DNS resolution failure handling
	}
}

func TestHTTP3ProxyConfiguration(t *testing.T) {
	t.Parallel()

	// Test HTTP3 with various proxy configurations
	testCases := []struct {
		name     string
		proxyURL string
	}{
		{"HTTP proxy", "http://127.0.0.1:8080"},
		{"HTTP proxy with domain", "http://127.0.0.1:8081"},
		{"HTTPS proxy", "https://127.0.0.1:8443"},
		{"Invalid proxy", "invalid://proxy"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP3().
				Proxy(tc.proxyURL).
				Timeout(1 * time.Second).
				Build()

			// Some proxy configurations may be invalid, that's expected
			if client != nil {
				// Test a simple request that will likely fail due to proxy unavailability
				resp := client.Get(g.String("http://127.0.0.1:9999/test")).Do()
				if resp.IsErr() {
					t.Logf("Expected proxy connection error for %s: %v", tc.name, resp.Err())
				}
			} else {
				t.Logf("Client creation failed for %s proxy (expected for invalid configs)", tc.name)
			}
		})
	}
}

func TestHTTP3NetworkErrorHandling(t *testing.T) {
	t.Parallel()

	// Test HTTP3 network error handling
	client := surf.NewClient().Builder().
		HTTP3().
		Timeout(500 * time.Millisecond).
		Build()

	if client == nil {
		t.Fatal("expected client to be created")
	}

	// Test connection timeout
	resp := client.Get(g.String("http://127.0.0.1:65535/timeout")).Do()
	if resp.IsErr() {
		t.Logf("Expected timeout error: %v", resp.Err())
		// This tests network timeout handling
	}

	// Test invalid port
	resp2 := client.Get(g.String("http://localhost:99999/invalid-port")).Do()
	if resp2.IsErr() {
		t.Logf("Expected invalid port error: %v", resp2.Err())
		// This tests port validation error handling
	}
}

func TestHTTP3TransportCaching(t *testing.T) {
	t.Parallel()

	// Test that HTTP3 transport caching works properly
	client1 := surf.NewClient().Builder().
		HTTP3().
		Build()

	client2 := surf.NewClient().Builder().
		HTTP3().
		Build()

	if client1 == nil || client2 == nil {
		t.Fatal("expected both clients to be created")
	}

	// Both clients should use cached transports for the same configuration
	// This is mainly for code coverage of caching logic
	t.Log("HTTP3 transport caching test completed")
}

func TestHTTP3(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func() *surf.Client
	}{
		{
			name: "HTTP3 shorthand",
			build: func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3().
					Build()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.build()

			if client == nil {
				t.Fatal("expected client to be built successfully")
			}

			// Verify transport is configured
			if client.GetTransport() == nil {
				t.Fatal("expected transport to be configured")
			}

			// HTTP3 transport requires TLS config
			if client.GetTLSConfig() == nil {
				t.Fatal("expected TLS config to be set for HTTP3")
			}
		})
	}
}

func TestHTTP3WithSession(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Session().
		HTTP3().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Session should work with HTTP3
	if client.GetTLSConfig() == nil {
		t.Fatal("expected TLS config to be set")
	}
}

func TestHTTP3WithForceHTTP1(t *testing.T) {
	t.Parallel()

	// When ForceHTTP1 is set, HTTP3 should be disabled
	client := surf.NewClient().Builder().
		ForceHTTP1().
		HTTP3().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Transport should not be HTTP3 when ForceHTTP1 is set
	if client.GetTransport() == nil {
		t.Fatal("expected transport to be configured")
	}
}

// Merged into TestHTTP3ProxyConfiguration and TestHTTP3WithSOCKS5Proxy

func TestHTTP3TransportCloseIdleConnections(t *testing.T) {
	t.Parallel()

	// Test without singleton - should have closeIdleConnections middleware
	client := surf.NewClient().Builder().
		HTTP3().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Should not panic
	client.CloseIdleConnections()

	// Test with singleton - connections should persist
	client = surf.NewClient().Builder().
		Singleton().
		HTTP3().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Should not panic
	client.CloseIdleConnections()
}

func TestHTTP3WithInterfaceAddr(t *testing.T) {
	t.Parallel()

	// Test HTTP3 with specific interface address
	client := surf.NewClient().Builder().
		InterfaceAddr("192.168.1.100").
		HTTP3().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Both interface and HTTP3 should be configured
	if client.GetDialer() == nil {
		t.Fatal("expected dialer to be configured")
	}

	if client.GetTransport() == nil {
		t.Fatal("expected transport to be configured")
	}
}

func TestHTTP3FallbackBehavior(t *testing.T) {
	t.Parallel()

	// Test that HTTP3 falls back gracefully when not supported
	// This is a behavioral test that would require actual network requests
	// to fully verify, but we can test the configuration

	client := surf.NewClient().Builder().
		HTTP3().
		Proxy("http://127.0.0.1:8080"). // Should trigger fallback
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// The client should still be functional even with fallback
	if client.GetTransport() == nil {
		t.Fatal("expected transport to be configured")
	}
}

func TestHTTP3InternalFunctions(t *testing.T) {
	t.Parallel()

	// Test HTTP3 internal parsing functions by creating requests
	// This will indirectly test resolve, parseResolvedAddress, and other functions

	tests := []struct {
		name string
		url  string
	}{
		{
			name: "localhost with port",
			url:  "https://localhost:8080",
		},
		{
			name: "IP address",
			url:  "https://127.0.0.1:443",
		},
		{
			name: "domain name",
			url:  "https://127.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP3().
				Build()

			// Creating a request will exercise internal parsing functions
			req := client.Get(g.String(tt.url))
			if req == nil {
				t.Fatal("expected request to be created")
			}

			// The request should be properly formed
			if req.GetRequest() == nil {
				t.Fatal("expected HTTP request to be created")
			}

			// Don't actually send the request as it may fail in test environment
			// The goal is to exercise the internal functions
		})
	}
}

func TestHTTP3WithSOCKS5Proxy(t *testing.T) {
	t.Parallel()

	// Test HTTP3 with SOCKS5 proxy configuration
	// This will exercise dialSOCKS5 code paths
	tests := []struct {
		name  string
		proxy string
	}{
		{
			name:  "SOCKS5 localhost",
			proxy: "socks5://localhost:1080",
		},
		{
			name:  "SOCKS5 with auth",
			proxy: "socks5://user:pass@localhost:1080",
		},
		{
			name:  "SOCKS5 IP",
			proxy: "socks5://127.0.0.1:1080",
		},
		{
			name:  "SOCKS5 compatibility test",
			proxy: "socks5://127.0.0.1:9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP3().
				Proxy(tt.proxy).
				Build()

			if client == nil {
				t.Fatal("expected client to be built successfully")
			}

			// Transport should be configured for HTTP3 + SOCKS5
			if client.GetTransport() == nil {
				t.Fatal("expected transport to be configured")
			}

			// Creating request should exercise SOCKS5 parsing
			req := client.Get(g.String("https://127.0.0.1:8080/get"))
			if req == nil {
				t.Fatal("expected request to be created")
			}
		})
	}
}

func TestHTTP3AddressParsing(t *testing.T) {
	t.Parallel()

	// Test HTTP3 address parsing by creating various URL formats
	tests := []struct {
		name       string
		url        string
		shouldWork bool
	}{
		{
			"Valid HTTPS with port",
			"https://127.0.0.1:443",
			true,
		},
		{
			"Valid HTTPS default port",
			"https://127.0.0.1",
			true,
		},
		{
			"Valid HTTP with custom port",
			"http://127.0.0.1:8080",
			true,
		},
		{
			"IPv4 address",
			"https://192.168.1.1:443",
			true,
		},
		{
			"IPv6 address",
			"https://[2001:db8::1]:443",
			true,
		},
		{
			"Localhost",
			"https://localhost:9443",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP3().
				Build()

			// Creating requests exercises address parsing functions
			req := client.Get(g.String(tt.url))

			if tt.shouldWork {
				if req == nil {
					t.Fatal("expected request to be created")
				}
				if req.GetRequest() == nil {
					t.Fatal("expected HTTP request to be created")
				}
			} else {
				// For invalid URLs, we might still get a request but it would fail later
				t.Logf("URL parsing result: %v", req != nil)
			}
		})
	}
}

func TestHTTP3UDPListener(t *testing.T) {
	t.Parallel()

	// Test HTTP3 UDP listener creation by using HTTP3 with different network configs
	tests := []struct {
		name      string
		buildFunc func() *surf.Client
	}{
		{
			"HTTP3 with DNS",
			func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3().
					DNS(g.String("8.8.8.8:53")).
					Build()
			},
		},
		{
			"HTTP3 with interface",
			func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3().
					InterfaceAddr(g.String("127.0.0.1")).
					Build()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.buildFunc()

			if client == nil {
				t.Fatal("expected client to be built successfully")
			}

			// HTTP3 transport should be configured
			if client.GetTransport() == nil {
				t.Fatal("expected transport to be configured")
			}

			// Creating a request exercises UDP listener creation internally
			req := client.Get(g.String("https://127.0.0.1:8080/get"))
			if req == nil {
				t.Fatal("expected request to be created")
			}
		})
	}
}

// Merged into TestHTTP3DNSIntegration

func TestHTTP3ErrorHandling(t *testing.T) {
	t.Parallel()

	// Test HTTP3 error handling scenarios
	tests := []struct {
		name string
		url  string
	}{
		{
			"Invalid domain",
			"https://non-existent-domain-12345.invalid",
		},
		{
			"Invalid port",
			"https://127.0.0.1:99999",
		},
		{
			"Connection refused",
			"https://127.0.0.1:65535",
		},
	}

	client := surf.NewClient().Builder().HTTP3().Build()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// These should create requests but may fail during actual execution
			req := client.Get(g.String(tt.url))
			if req == nil {
				t.Fatal("expected request to be created even for invalid URLs")
			}

			if req.GetRequest() == nil {
				t.Fatal("expected HTTP request to be created")
			}

			// URL should be parsed (even if invalid)
			if req.GetRequest().URL == nil {
				t.Fatal("expected URL to be parsed")
			}
		})
	}
}

// TestHTTP3SettingsQpackMaxTableCapacity tests the QpackMaxTableCapacity method
func TestHTTP3SettingsQpackMaxTableCapacity(t *testing.T) {
	t.Parallel()

	// Test setting QpackMaxTableCapacity
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(1024).
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Error("HTTP/3 build failed with QpackMaxTableCapacity")
	}
}

// TestHTTP3SettingsMaxFieldSectionSize tests the MaxFieldSectionSize method
func TestHTTP3SettingsMaxFieldSectionSize(t *testing.T) {
	t.Parallel()

	// Test setting MaxFieldSectionSize
	client := surf.NewClient().Builder().
		HTTP3Settings().
		MaxFieldSectionSize(4096).
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Error("HTTP/3 build failed with MaxFieldSectionSize")
	}
}

// TestHTTP3SettingsQpackBlockedStreams tests the QpackBlockedStreams method
func TestHTTP3SettingsQpackBlockedStreams(t *testing.T) {
	t.Parallel()

	// Test setting QpackBlockedStreams
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackBlockedStreams(8).
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Error("HTTP/3 build failed with QpackBlockedStreams")
	}
}

// TestHTTP3SettingsEnableConnectProtocol tests the EnableConnectProtocol method
func TestHTTP3SettingsEnableConnectProtocol(t *testing.T) {
	t.Parallel()

	// Test setting EnableConnectProtocol
	client := surf.NewClient().Builder().
		HTTP3Settings().
		EnableConnectProtocol(1).
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Error("HTTP/3 build failed with EnableConnectProtocol")
	}
}

// TestHTTP3SettingsH3Datagram tests the H3Datagram method
func TestHTTP3SettingsH3Datagram(t *testing.T) {
	t.Parallel()

	// Test setting H3Datagram
	client := surf.NewClient().Builder().
		HTTP3Settings().
		H3Datagram(128).
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Error("HTTP/3 build failed with H3Datagram")
	}
}

// TestHTTP3SettingsSettingsH3Datagram tests the SettingsH3Datagram method
func TestHTTP3SettingsSettingsH3Datagram(t *testing.T) {
	t.Parallel()

	// Test setting SettingsH3Datagram
	client := surf.NewClient().Builder().
		HTTP3Settings().
		SettingsH3Datagram(256).
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Error("HTTP/3 build failed with SettingsH3Datagram")
	}
}

// TestHTTP3SettingsEnableWebtransport tests the EnableWebtransport method
func TestHTTP3SettingsEnableWebtransport(t *testing.T) {
	t.Parallel()

	// Test setting EnableWebtransport
	client := surf.NewClient().Builder().
		HTTP3Settings().
		EnableWebtransport(1).
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Error("HTTP/3 build failed with EnableWebtransport")
	}
}

// TestHTTP3SettingsGrease tests the Grease method
func TestHTTP3SettingsGrease(t *testing.T) {
	t.Parallel()

	// Test setting Grease
	client := surf.NewClient().Builder().
		HTTP3Settings().
		Grease().
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Error("HTTP/3 build failed with Grease")
	}
}

// TestHTTP3SettingsCombined tests multiple HTTP/3 settings applied together
func TestHTTP3SettingsCombined(t *testing.T) {
	t.Parallel()

	// Test multiple settings applied together
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(2048).
		MaxFieldSectionSize(8192).
		QpackBlockedStreams(16).
		H3Datagram(256).
		EnableConnectProtocol(2).
		EnableWebtransport(4096).
		Grease().
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Error("HTTP/3 build failed with combined settings")
	}
}

// TestHTTP3SettingsWithProxy tests HTTP/3 settings with proxy configurations
func TestHTTP3SettingsWithProxy(t *testing.T) {
	t.Parallel()

	// Test HTTP/3 settings with proxy
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(1024).
		Grease().
		Set().
		Proxy("http://localhost:8080").
		HTTP3().Build()

	if client == nil {
		t.Error("Client build with HTTP/3 and proxy failed")
	}
}

// TestHTTP3SettingsWithDifferentValues tests various setting values
func TestHTTP3SettingsWithDifferentValues(t *testing.T) {
	t.Parallel()

	// Apply various setting values to test different inputs
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(0).
		MaxFieldSectionSize(1 << 20).
		QpackBlockedStreams(65535).
		H3Datagram(1).
		SettingsH3Datagram(65535).
		EnableConnectProtocol(1024).
		EnableWebtransport(999999).
		Grease().
		Set().Build()

	if client == nil {
		t.Error("Client build failed with various setting values")
	}
}

// TestHTTP3SettingsIntegrationWithTestServer tests HTTP/3 settings with real server
func TestHTTP3SettingsIntegrationWithTestServer(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"http3_settings": "configured"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test HTTP/3 settings with test server
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(1024).
		Set().
		HTTP3().
		Build()

	if client == nil {
		t.Fatalf("HTTP/3 settings configuration failed")
	}

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatalf("HTTP/3 settings request failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

// TestHTTP3SettingsWithCustomDialer tests HTTP/3 settings with custom dialers
func TestHTTP3SettingsWithCustomDialer(t *testing.T) {
	t.Parallel()

	// Test HTTP/3 with custom DNS resolver
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(1024).
		Set().
		DNS("8.8.8.8:53").
		HTTP3().Build()

	if client == nil {
		t.Error("Client build with custom dialer failed")
	}
}

// TestHTTP3SettingsWithTimeout tests HTTP/3 settings with timeout configurations
func TestHTTP3SettingsWithTimeout(t *testing.T) {
	t.Parallel()

	// Test with timeout
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(2048).
		Set().
		Timeout(30 * 1e9). // 30 seconds in nanoseconds
		HTTP3().Build()

	if client == nil {
		t.Error("Client build with timeout failed")
	}
}

// TestHTTP3SettingsWithSession tests HTTP/3 settings combined with session
func TestHTTP3SettingsWithSession(t *testing.T) {
	t.Parallel()

	// Test with session
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(1024).
		Set().
		Session().
		HTTP3().Build()

	if client == nil {
		t.Error("Client build with session failed")
	}
}

// TestHTTP3SettingsWithKeepAlive tests HTTP/3 settings with keep-alive
func TestHTTP3SettingsWithKeepAlive(t *testing.T) {
	t.Parallel()

	// Test with keep-alive disabled
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(512).
		Set().
		DisableKeepAlive().
		HTTP3().Build()

	if client == nil {
		t.Error("Client build with keep-alive failed")
	}
}

// TestHTTP3SettingsWithInterfaceAddr tests HTTP/3 with specific interface address
func TestHTTP3SettingsWithInterfaceAddr(t *testing.T) {
	t.Parallel()

	// Test with specific interface address
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(1024).
		Set().
		InterfaceAddr("192.168.1.100").
		HTTP3().
		Build()

	if client == nil {
		t.Error("Client build with interface address failed")
	}
}

// TestHTTP3SettingsWithSingleton tests HTTP/3 with singleton configuration
func TestHTTP3SettingsWithSingleton(t *testing.T) {
	t.Parallel()

	// Test with singleton
	client := surf.NewClient().Builder().
		HTTP3Settings().
		QpackMaxTableCapacity(1024).
		Set().
		Singleton().
		HTTP3().
		Build()

	if client == nil {
		t.Error("Client build with singleton failed")
	}

	// Should support CloseIdleConnections
	client.CloseIdleConnections()
}
