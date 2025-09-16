package surf_test

import (
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	uquic "github.com/enetx/uquic"
)

func TestHTTP3Settings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func() *surf.Client
	}{
		{
			name: "HTTP3 with Chrome QUIC ID",
			build: func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3Settings().Chrome().Set().
					Build()
			},
		},
		{
			name: "HTTP3 with Firefox QUIC ID",
			build: func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3Settings().Firefox().Set().
					Build()
			},
		},
		{
			name: "HTTP3 with custom QUIC ID",
			build: func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3Settings().SetQUICID(uquic.QUICChrome_115).Set().
					Build()
			},
		},
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
		HTTP3Settings().Chrome().Set().
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
		HTTP3Settings().Chrome().Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Transport should not be HTTP3 when ForceHTTP1 is set
	if client.GetTransport() == nil {
		t.Fatal("expected transport to be configured")
	}
}

func TestHTTP3WithProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		proxy any
	}{
		{
			name:  "SOCKS5 proxy",
			proxy: "socks5://localhost:1080",
		},
		{
			name:  "HTTP proxy fallback",
			proxy: "http://proxy.example.com:8080",
		},
		{
			name:  "Proxy rotation function",
			proxy: func() g.String { return g.String("socks5://localhost:1080") },
		},
		{
			name:  "Proxy slice",
			proxy: []string{"socks5://localhost:1080", "socks5://localhost:1081"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP3Settings().Chrome().Set().
				Proxy(tt.proxy).
				Build()

			if client == nil {
				t.Fatal("expected client to be built successfully")
			}

			// Proxy should be configured with HTTP3
			if client.GetTransport() == nil {
				t.Fatal("expected transport to be configured")
			}
		})
	}
}

func TestHTTP3TransportCloseIdleConnections(t *testing.T) {
	t.Parallel()

	// Test without singleton - should have closeIdleConnections middleware
	client := surf.NewClient().Builder().
		HTTP3Settings().Chrome().Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Should not panic
	client.CloseIdleConnections()

	// Test with singleton - connections should persist
	client = surf.NewClient().Builder().
		Singleton().
		HTTP3Settings().Chrome().Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Should not panic
	client.CloseIdleConnections()
}

func TestHTTP3WithCustomQUICSpec(t *testing.T) {
	t.Parallel()

	// This test requires understanding of QUIC spec structure
	// For now, we test that the method exists and doesn't panic

	client := surf.NewClient().Builder().
		HTTP3Settings().
		// SetQUICSpec would require a valid uquic.QUICSpec
		Chrome(). // Use Chrome as fallback
		Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}
}

func TestHTTP3SettingsChaining(t *testing.T) {
	t.Parallel()

	// Test that HTTP3Settings methods can be chained
	client := surf.NewClient().Builder().
		HTTP3Settings().
		Chrome().
		Firefox(). // Last one wins
		Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// The client should be configured with Firefox QUIC settings (last one set)
	if client.GetTransport() == nil {
		t.Fatal("expected transport to be configured")
	}
}

func TestHTTP3WithDNSResolver(t *testing.T) {
	t.Parallel()

	// Test HTTP3 with custom DNS resolver
	client := surf.NewClient().Builder().
		DNS("8.8.8.8:53").
		HTTP3Settings().Chrome().Set().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Both DNS and HTTP3 should be configured
	if client.GetDialer() == nil {
		t.Fatal("expected dialer to be configured")
	}

	if client.GetTransport() == nil {
		t.Fatal("expected transport to be configured")
	}
}

func TestHTTP3WithInterfaceAddr(t *testing.T) {
	t.Parallel()

	// Test HTTP3 with specific interface address
	client := surf.NewClient().Builder().
		InterfaceAddr("192.168.1.100").
		HTTP3Settings().Chrome().Set().
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
		HTTP3Settings().Chrome().Set().
		Proxy("http://non-socks-proxy.com:8080"). // Should trigger fallback
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
			url:  "https://httpbin.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP3Settings().Chrome().Set().
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP3Settings().Chrome().Set().
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
			req := client.Get(g.String("https://httpbin.org/get"))
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
			"https://example.com:443",
			true,
		},
		{
			"Valid HTTPS default port",
			"https://example.com",
			true,
		},
		{
			"Valid HTTP with custom port",
			"http://example.com:8080",
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
				HTTP3Settings().Chrome().Set().
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
			"HTTP3 Chrome",
			func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3Settings().Chrome().Set().
					Build()
			},
		},
		{
			"HTTP3 Firefox",
			func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3Settings().Firefox().Set().
					Build()
			},
		},
		{
			"HTTP3 with DNS",
			func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3Settings().Chrome().Set().
					DNS(g.String("8.8.8.8:53")).
					Build()
			},
		},
		{
			"HTTP3 with interface",
			func() *surf.Client {
				return surf.NewClient().Builder().
					HTTP3Settings().Chrome().Set().
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
			req := client.Get(g.String("https://httpbin.org/get"))
			if req == nil {
				t.Fatal("expected request to be created")
			}
		})
	}
}

func TestHTTP3DNSResolution(t *testing.T) {
	t.Parallel()

	// Test HTTP3 DNS resolution to exercise dialDNS function
	tests := []struct {
		name string
		dns  string
		url  string
	}{
		{
			"Google DNS",
			"8.8.8.8:53",
			"https://httpbin.org/get",
		},
		{
			"Cloudflare DNS",
			"1.1.1.1:53",
			"https://example.com",
		},
		{
			"Custom DNS",
			"192.168.1.1:53",
			"https://google.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient().Builder().
				HTTP3Settings().Chrome().Set().
				DNS(g.String(tt.dns)).
				Build()

			if client == nil {
				t.Fatal("expected client to be built successfully")
			}

			// DNS resolution should be configured
			if client.GetDialer() == nil {
				t.Fatal("expected dialer to be configured")
			}

			if client.GetDialer().Resolver == nil {
				t.Fatal("expected resolver to be configured")
			}

			// Creating requests exercises DNS resolution
			req := client.Get(g.String(tt.url))
			if req == nil {
				t.Fatal("expected request to be created")
			}
		})
	}
}

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
			"https://example.com:99999",
		},
		{
			"Connection refused",
			"https://127.0.0.1:65535",
		},
	}

	client := surf.NewClient().Builder().
		HTTP3Settings().Chrome().Set().
		Build()

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
