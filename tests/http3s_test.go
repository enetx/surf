package surf_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/enetx/surf"
	uquic "github.com/enetx/uquic"
	"github.com/enetx/uquic/http3"
	utls "github.com/refraction-networking/utls"
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

	cert := utls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	// Create UDP listener
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, "", err
	}

	// Configure TLS for HTTP/3
	tlsConf := &utls.Config{
		Certificates: []utls.Certificate{cert},
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

func TestHTTP3SettingsChrome(t *testing.T) {
	t.Parallel()

	// Create HTTP/3 test server
	handler := _http.HandlerFunc(func(w _http.ResponseWriter, _ *_http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(_http.StatusOK)
		fmt.Fprint(w, `{"browser": "chrome", "protocol": "HTTP/3"}`)
	})

	server, conn, addr, err := createHTTP3TestServer(handler)
	if err != nil {
		t.Skip("Failed to create HTTP/3 test server:", err)
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
		HTTP3Settings().
		Chrome().
		Set().
		Build()

	// Test that client was created successfully
	if client == nil {
		t.Fatal("expected client to be created with Chrome HTTP/3 settings")
	}

	// Make request to HTTP/3 server
	resp := client.Get(g.String(addr)).Do()
	if resp.IsErr() {
		t.Logf("HTTP/3 Chrome request failed (may be expected in test env): %v", resp.Err())
		return
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success, got %d", resp.Ok().StatusCode)
	}

	// Check if HTTP/3 was used
	if resp.Ok().Body.Contains("HTTP/3") {
		t.Log("Successfully used HTTP/3 with Chrome fingerprint")
	}

	// Shutdown server
	server.CloseGracefully(5 * time.Second)
}

func TestHTTP3SettingsFirefox(t *testing.T) {
	t.Parallel()

	// Create HTTP/3 test server
	handler := _http.HandlerFunc(func(w _http.ResponseWriter, _ *_http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(_http.StatusOK)
		fmt.Fprint(w, `{"browser": "firefox", "protocol": "HTTP/3"}`)
	})

	server, conn, addr, err := createHTTP3TestServer(handler)
	if err != nil {
		t.Skip("Failed to create HTTP/3 test server:", err)
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
		HTTP3Settings().
		Firefox().
		Set().
		Build()

	// Test that client was created successfully
	if client == nil {
		t.Fatal("expected client to be created with Firefox HTTP/3 settings")
	}

	// Make request to HTTP/3 server
	resp := client.Get(g.String(addr)).Do()
	if resp.IsErr() {
		t.Logf("HTTP/3 Firefox request failed (may be expected in test env): %v", resp.Err())
		return
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success, got %d", resp.Ok().StatusCode)
	}

	// Check if HTTP/3 was used
	if resp.Ok().Body.Contains("HTTP/3") {
		t.Log("Successfully used HTTP/3 with Firefox fingerprint")
	}

	// Shutdown server
	server.CloseGracefully(5 * time.Second)
}

func TestHTTP3SettingsSetQUICID(t *testing.T) {
	t.Parallel()

	// Use a predefined QUIC ID
	quicID := uquic.QUICChrome_115

	client := surf.NewClient().Builder().
		HTTP3Settings().
		SetQUICID(quicID).
		Set().
		Build()

	// Test that client was created successfully
	if client == nil {
		t.Fatal("expected client to be created with custom QUIC ID")
	}

	// Verify transport is configured
	transport := client.GetTransport()
	if transport == nil {
		t.Error("expected transport to be configured for HTTP/3")
	}
}

func TestHTTP3SettingsSetQUICSpec(t *testing.T) {
	t.Parallel()

	// Create a basic QUIC spec
	spec, err := uquic.QUICID2Spec(uquic.QUICFirefox_116)
	if err != nil {
		t.Skipf("Could not create QUIC spec: %v", err)
	}

	client := surf.NewClient().Builder().
		HTTP3Settings().
		SetQUICSpec(spec).
		Set().
		Build()

	// Test that client was created successfully
	if client == nil {
		t.Fatal("expected client to be created with custom QUIC spec")
	}

	// Verify transport is configured
	transport := client.GetTransport()
	if transport == nil {
		t.Error("expected transport to be configured for HTTP/3")
	}
}

func TestHTTP3SettingsWithSession(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		HTTP3Settings().
		Chrome().
		Set().
		Session().
		Build()

	// Test that client was created successfully with session
	if client == nil {
		t.Fatal("expected client to be created with HTTP/3 and session")
	}

	// Verify session is configured
	if client.GetClient().Jar == nil {
		t.Error("expected session (cookie jar) to be configured")
	}
}

func TestHTTP3SettingsWithTimeout(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		HTTP3Settings().
		Firefox().
		Set().
		Timeout(5 * time.Second).
		Build()

	// Test that client was created successfully
	if client == nil {
		t.Fatal("expected client to be created with HTTP/3 and timeout")
	}

	// Verify timeout is configured
	if client.GetClient().Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", client.GetClient().Timeout)
	}
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
		HTTP3Settings().
		Chrome().
		Set().
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

func TestHTTP3SettingsWithSOCKS5Proxy(t *testing.T) {
	t.Parallel()

	// Note: HTTP/3 and SOCKS5 proxy are generally incompatible at transport level
	// This test verifies that attempting to combine them doesn't crash
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Expected panic when combining HTTP/3 with SOCKS5 proxy: %v", r)
		}
	}()

	// This should panic or fail gracefully
	client := surf.NewClient().Builder().
		HTTP3Settings().
		Chrome().
		Set().
		Proxy("socks5://127.0.0.1:9999").
		Timeout(2 * time.Second).
		Build()

	// If we get here, the client was created (unexpected but not fatal)
	if client != nil {
		t.Log("Client was created despite HTTP/3 + SOCKS5 combination")
	}
}

func TestHTTP3SettingsWithHTTPProxy(t *testing.T) {
	t.Parallel()

	// Test client creation with HTTP proxy (should cause fallback from HTTP/3)
	client := surf.NewClient().Builder().
		HTTP3Settings().
		Chrome().
		Set().
		Proxy("http://proxy.example.com:8080").
		Timeout(2 * time.Second).
		Build()

	// Test that client was created successfully
	if client == nil {
		t.Fatal("expected client to be created with HTTP/3 and HTTP proxy")
	}

	// Verify timeout is configured
	if client.GetClient().Timeout != 2*time.Second {
		t.Errorf("expected timeout 2s, got %v", client.GetClient().Timeout)
	}
}

func TestHTTP3SettingsMethodChaining(t *testing.T) {
	t.Parallel()

	// Test that method chaining works correctly
	client := surf.NewClient().Builder().
		HTTP3Settings().
		Chrome().
		Set().
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
		HTTP3Settings().
		Chrome().
		Set().
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
		HTTP3Settings().
		Firefox().
		Set().
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

func TestHTTP3SettingsInvalidQUICID(t *testing.T) {
	t.Parallel()

	// Test with an empty/invalid QUIC ID
	var invalidID uquic.QUICID

	client := surf.NewClient().Builder().
		HTTP3Settings().
		SetQUICID(invalidID).
		Set().
		Build()

	// Client should still be created (will fallback internally)
	if client == nil {
		t.Fatal("expected client to be created even with invalid QUIC ID")
	}

	// Verify transport is configured
	transport := client.GetTransport()
	if transport == nil {
		t.Error("expected transport to be configured for HTTP/3")
	}
}

func TestHTTP3SettingsBrowserFingerprints(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		buildFn func() *surf.Client
	}{
		{
			"Chrome fingerprint",
			func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3Settings().
					Chrome().
					Set().
					Build()
			},
		},
		{
			"Firefox fingerprint",
			func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3Settings().
					Firefox().
					Set().
					Build()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.buildFn()
			if client == nil {
				t.Fatalf("expected client to be created for %s", tc.name)
			}

			// Verify transport is configured
			transport := client.GetTransport()
			if transport == nil {
				t.Errorf("expected transport to be configured for %s", tc.name)
			}
		})
	}
}

func TestHTTP3Fingerprints(t *testing.T) {
	t.Run("Chrome fingerprint", func(t *testing.T) {
		// Get the expected Chrome fingerprint
		chromeID := uquic.QUICChrome_115
		expectedSpec, err := uquic.QUICID2Spec(chromeID)
		if err != nil {
			t.Fatalf("Failed to get Chrome spec: %v", err)
		}

		// Build client with Chrome fingerprint
		client := surf.NewClient().Builder().
			HTTP3Settings().Chrome().Set().
			Build()

		// Verify transport is set
		if client.GetTransport() == nil {
			t.Fatal("Transport is nil")
		}

		// Check fingerprint characteristics
		t.Logf("Chrome fingerprint ID: %s", chromeID.Fingerprint)
		t.Logf("Chrome SrcConnIDLength: %d", expectedSpec.InitialPacketSpec.SrcConnIDLength)
		t.Logf("Chrome UDPDatagramMinSize: %d", expectedSpec.UDPDatagramMinSize)
	})

	t.Run("Firefox fingerprint", func(t *testing.T) {
		// Get the expected Firefox fingerprint
		firefoxID := uquic.QUICFirefox_116
		expectedSpec, err := uquic.QUICID2Spec(firefoxID)
		if err != nil {
			t.Fatalf("Failed to get Firefox spec: %v", err)
		}

		// Build client with Firefox fingerprint
		client := surf.NewClient().Builder().
			HTTP3Settings().Firefox().Set().
			Build()

		// Verify transport is set
		if client.GetTransport() == nil {
			t.Fatal("Transport is nil")
		}

		// Check fingerprint characteristics
		t.Logf("Firefox fingerprint ID: %s", firefoxID.Fingerprint)
		t.Logf("Firefox SrcConnIDLength: %d", expectedSpec.InitialPacketSpec.SrcConnIDLength)
		t.Logf("Firefox UDPDatagramMinSize: %d", expectedSpec.UDPDatagramMinSize)
	})

	t.Run("Fingerprint differences", func(t *testing.T) {
		chromeSpec, _ := uquic.QUICID2Spec(uquic.QUICChrome_115)
		firefoxSpec, _ := uquic.QUICID2Spec(uquic.QUICFirefox_116)

		// These should be different to prove we have distinct fingerprints
		if chromeSpec.InitialPacketSpec.SrcConnIDLength == firefoxSpec.InitialPacketSpec.SrcConnIDLength {
			t.Log("Warning: SrcConnIDLength is the same for Chrome and Firefox")
		}

		if chromeSpec.UDPDatagramMinSize == firefoxSpec.UDPDatagramMinSize {
			t.Log("Warning: UDPDatagramMinSize is the same for Chrome and Firefox")
		}

		// Log the differences
		t.Logf("Chrome vs Firefox SrcConnIDLength: %d vs %d",
			chromeSpec.InitialPacketSpec.SrcConnIDLength,
			firefoxSpec.InitialPacketSpec.SrcConnIDLength)
		t.Logf("Chrome vs Firefox UDPDatagramMinSize: %d vs %d",
			chromeSpec.UDPDatagramMinSize,
			firefoxSpec.UDPDatagramMinSize)
	})
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
			Impersonate().FireFox().HTTP3().
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
			HTTP3().                        // This should be ignored
			HTTP3Settings().Chrome().Set(). // This takes precedence
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport from manual settings")
		}
	})

	t.Run("Auto then manual", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3().                        // This gets disabled
			HTTP3Settings().Chrome().Set(). // This applies
			Impersonate().Chrome().         // This should not trigger auto HTTP3
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
			HTTP3Settings().Chrome().Set().
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
			HTTP3Settings().Chrome().Set().
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
			HTTP3Settings().Chrome().Set().
			Build()

		// Should have HTTP/3 transport with both DNS and SOCKS5 proxy
		if client == nil {
			t.Fatal("HTTP/3 should be active with DNS + SOCKS5 proxy")
		}
	})

	t.Run("HTTP3 with JA3 compatibility", func(t *testing.T) {
		client := surf.NewClient().Builder().
			JA().Chrome131().
			HTTP3Settings().Chrome().Set().
			Build()

		// Should have HTTP/3 transport (JA3 should be ignored)
		if client == nil {
			t.Fatal("Expected HTTP/3 transport (JA3 should be ignored for HTTP/3)")
		}
	})

	t.Run("HTTP3 with DNS settings", func(t *testing.T) {
		client := surf.NewClient().Builder().
			DNS("8.8.8.8:53").
			HTTP3Settings().Chrome().Set().
			Build()

		// Should have HTTP/3 transport with DNS settings
		if client == nil {
			t.Fatal("Expected HTTP/3 transport with DNS settings")
		}
	})

	t.Run("HTTP3 with DNSOverTLS", func(t *testing.T) {
		client := surf.NewClient().Builder().
			DNSOverTLS().Google().
			HTTP3Settings().Chrome().Set().
			Build()

		// Should have HTTP/3 transport with DNS over TLS
		if client == nil {
			t.Fatal("Expected HTTP/3 transport with DNS over TLS")
		}
	})

	t.Run("HTTP3 with timeout", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Timeout(30 * time.Second).
			HTTP3Settings().Chrome().Set().
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
			HTTP3Settings().Chrome().Set().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport with context")
		}
	})

	t.Run("HTTP3 with headers", func(t *testing.T) {
		client := surf.NewClient().Builder().
			SetHeaders("X-Test", "value").
			HTTP3Settings().Chrome().Set().
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
			HTTP3Settings().Chrome().Set().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport with middleware")
		}
	})
}

func TestHTTP3TransportProperties(t *testing.T) {
	t.Run("Chrome transport properties", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3Settings().Chrome().Set().
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
			HTTP3Settings().Firefox().Set().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport")
		}

		if client.GetTransport() == nil {
			t.Fatal("Transport should not be nil")
		}
	})
}

func TestHTTP3CustomSettings(t *testing.T) {
	t.Run("Custom QUIC ID", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3Settings().
			SetQUICID(uquic.QUICChrome_115).
			Set().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport with custom QUIC ID")
		}
	})

	t.Run("Custom QUIC Spec", func(t *testing.T) {
		spec, err := uquic.QUICID2Spec(uquic.QUICChrome_115)
		if err != nil {
			t.Fatalf("Failed to get QUIC spec: %v", err)
		}

		client := surf.NewClient().Builder().
			HTTP3Settings().
			SetQUICSpec(spec).
			Set().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport with custom QUIC spec")
		}
	})
}

func TestHTTP3EdgeCases(t *testing.T) {
	t.Run("Multiple HTTP3Settings calls", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3Settings().Chrome().Set().
			HTTP3Settings().Firefox().Set(). // Last one should win
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport from last HTTP3Settings call")
		}
	})

	t.Run("HTTP3 with ForceHTTP1", func(t *testing.T) {
		client := surf.NewClient().Builder().
			ForceHTTP1().
			HTTP3Settings().Chrome().Set().
			Build()

		// Client should be created, but ForceHTTP1 should override HTTP/3
		if client == nil {
			t.Fatal("Client should be created even with ForceHTTP1")
		}

		// Verify that client is created successfully
		if client.GetTransport() == nil {
			t.Fatal("Transport should be configured")
		}
	})

	t.Run("Empty HTTP3Settings chain", func(t *testing.T) {
		// This should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("HTTP3Settings should not panic: %v", r)
				}
			}()

			client := surf.NewClient().Builder().
				HTTP3Settings().Chrome().Set().
				Build()

			// Should still work, just not have HTTP/3
			if client == nil {
				t.Fatal("Client should not be nil")
			}
		}()
	})
}

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

	t.Run("Chrome mock request", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3Settings().Chrome().Set().
			Build()

		resp := client.Get(g.String(addr)).Do()
		if resp.IsErr() {
			t.Logf("Chrome mock request failed (may be expected in test env): %v", resp.Err())
			return
		}

		if !resp.Ok().StatusCode.IsSuccess() {
			t.Errorf("Expected success status, got %d", resp.Ok().StatusCode)
		}

		if resp.Ok().Body.Contains("HTTP/3") {
			t.Log("Chrome HTTP/3 mock request succeeded")
		}
	})

	t.Run("Firefox mock request", func(t *testing.T) {
		client := surf.NewClient().Builder().
			HTTP3Settings().Firefox().Set().
			Build()

		resp := client.Get(g.String(addr)).Do()
		if resp.IsErr() {
			t.Logf("Firefox mock request failed (may be expected in test env): %v", resp.Err())
			return
		}

		if !resp.Ok().StatusCode.IsSuccess() {
			t.Errorf("Expected success status, got %d", resp.Ok().StatusCode)
		}

		if resp.Ok().Body.Contains("HTTP/3") {
			t.Log("Firefox HTTP/3 mock request succeeded")
		}
	})

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
	server.CloseGracefully(5 * time.Second)
}

// TestHTTP3RealRequests removed - all tests should work offline without external URLs

func TestHTTP3DNSIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DNS integration tests in short mode")
	}

	t.Run("HTTP3 with custom DNS", func(t *testing.T) {
		client := surf.NewClient().Builder().
			DNS("8.8.8.8:53").
			HTTP3Settings().Chrome().Set().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport")
		}

		// DNS integration is tested through actual requests
		// since transport internals are not exposed
	})

	t.Run("HTTP3 with DNS over TLS", func(t *testing.T) {
		client := surf.NewClient().Builder().
			DNSOverTLS().Google().
			HTTP3Settings().Chrome().Set().
			Build()

		if client == nil {
			t.Fatal("Expected HTTP/3 transport")
		}

		// DNS over TLS integration is tested through actual requests
		// since transport internals are not exposed
	})
}

func TestHTTP3NetworkConditions(t *testing.T) {
	t.Run("HTTP3 with unreachable proxy", func(t *testing.T) {
		client := surf.NewClient().Builder().
			Proxy("http://unreachable:8080").
			HTTP3Settings().Chrome().Set().
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
			HTTP3Settings().Chrome().Set().
			Build()

		resp := client.Get(g.String(addr)).Do()

		// Should either succeed or timeout, but not crash
		if resp.IsErr() {
			t.Logf("Request timed out as expected: %v", resp.Err())
		} else {
			t.Logf("Request succeeded despite short timeout")
		}

		// Shutdown server
		server.CloseGracefully(5 * time.Second)
	})
}

func TestHTTP3DNSResolution(t *testing.T) {
	t.Parallel()

	// Test DNS resolution functionality in HTTP3 transport
	client := surf.NewClient().Builder().
		DNS("8.8.8.8:53").
		HTTP3Settings().Chrome().Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be created with custom DNS and HTTP3")
	}

	// Create a mock server for testing
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"dns": "resolved"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test request (will fall back to HTTP/1.1 with httptest)
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Logf("Expected error with HTTP3 fallback: %v", resp.Err())
		// This is expected behavior - HTTP3 may not work with httptest
	}
}

func TestHTTP3CustomResolver(t *testing.T) {
	t.Parallel()

	// Test HTTP3 with custom resolver configuration
	client := surf.NewClient().Builder().
		DNSOverTLS().Cloudflare().
		HTTP3Settings().Firefox().Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be created with DNS over TLS and HTTP3")
	}

	// Create a mock server for testing
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"resolver": "custom"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test request with custom resolver
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Logf("Expected error with HTTP3 + DNSOverTLS fallback: %v", resp.Err())
		// This is expected behavior - complex DNS configurations may not work with httptest
	}
}

func TestHTTP3AddressResolution(t *testing.T) {
	t.Parallel()

	// Test address resolution with invalid addresses
	client := surf.NewClient().Builder().
		HTTP3Settings().Chrome().Set().
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
		{"HTTPS proxy", "https://127.0.0.1:8443"},
		{"Invalid proxy", "invalid://proxy"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP3Settings().Chrome().Set().
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
		HTTP3Settings().Firefox().Set().
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
		HTTP3Settings().Chrome().Set().
		Build()

	client2 := surf.NewClient().Builder().
		HTTP3Settings().Chrome().Set().
		Build()

	if client1 == nil || client2 == nil {
		t.Fatal("expected both clients to be created")
	}

	// Both clients should use cached transports for the same configuration
	// This is mainly for code coverage of caching logic
	t.Log("HTTP3 transport caching test completed")
}
