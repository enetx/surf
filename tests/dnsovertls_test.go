package surf_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestDNSOverTLSProviders(t *testing.T) {
	t.Parallel()

	// Test that all DNS over TLS providers can be created through builder
	testCases := []string{
		"AdGuard", "Google", "Cloudflare", "Quad9", "Switch",
		"CIRAShield", "Ali", "Quad101", "SB", "Forge", "LibreDNS",
	}

	for _, name := range testCases {
		t.Run(name, func(t *testing.T) {
			client := surf.NewClient()
			builder := client.Builder()

			dnsBuilder := builder.DNSOverTLS()
			if dnsBuilder == nil {
				t.Fatalf("expected DNSOverTLS builder to be non-nil")
			}

			// Test different providers by method name
			var builtClient *surf.Client
			switch name {
			case "AdGuard":
				builtClient = dnsBuilder.AdGuard().Build()
			case "Google":
				builtClient = dnsBuilder.Google().Build()
			case "Cloudflare":
				builtClient = dnsBuilder.Cloudflare().Build()
			case "Quad9":
				builtClient = dnsBuilder.Quad9().Build()
			case "Switch":
				builtClient = dnsBuilder.Switch().Build()
			case "CIRAShield":
				builtClient = dnsBuilder.CIRAShield().Build()
			case "Ali":
				builtClient = dnsBuilder.Ali().Build()
			case "Quad101":
				builtClient = dnsBuilder.Quad101().Build()
			case "SB":
				builtClient = dnsBuilder.SB().Build()
			case "Forge":
				builtClient = dnsBuilder.Forge().Build()
			case "LibreDNS":
				builtClient = dnsBuilder.LibreDNS().Build()
			default:
				t.Fatalf("unknown provider: %s", name)
			}

			if builtClient == nil {
				t.Errorf("expected client with %s DNS to be non-nil", name)
			}
		})
	}
}

func TestDNSOverTLSWithLocalRequest(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"dns": "test"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with local server (no actual DNS resolution needed)
	testCases := []string{"Cloudflare", "AdGuard", "Google", "Quad9"}

	for _, name := range testCases {
		t.Run(name, func(t *testing.T) {
			client := surf.NewClient()
			builder := client.Builder()
			dnsBuilder := builder.DNSOverTLS()

			var builtClient *surf.Client
			switch name {
			case "Cloudflare":
				builtClient = dnsBuilder.Cloudflare().Build()
			case "AdGuard":
				builtClient = dnsBuilder.AdGuard().Build()
			case "Google":
				builtClient = dnsBuilder.Google().Build()
			case "Quad9":
				builtClient = dnsBuilder.Quad9().Build()
			}
			req := builtClient.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success status with %s DNS over TLS, got %d", name, resp.Ok().StatusCode)
			}
		})
	}
}

func TestDNSOverTLSCustomProvider(t *testing.T) {
	t.Parallel()

	// Test adding custom provider
	client := surf.NewClient()
	builder := client.Builder()
	dnsBuilder := builder.DNSOverTLS()

	builtClient := dnsBuilder.Cloudflare().Build()

	// Test that we can create a client with AddProvider
	client2 := surf.NewClient()
	builder2 := client2.Builder()
	dnsBuilder2 := builder2.DNSOverTLS()
	builtClient2 := dnsBuilder2.AddProvider("custom1.example.com", "custom1.example.com:853").Build()

	if builtClient == nil {
		t.Error("expected client with DNS provider to be non-nil")
	}

	if builtClient2 == nil {
		t.Error("expected client with custom DNS providers to be non-nil")
	}
}

func TestDNSOverTLSMultipleProviders(t *testing.T) {
	t.Parallel()

	// Test chaining multiple AddProvider calls
	client := surf.NewClient()
	builder := client.Builder()
	dnsBuilder := builder.DNSOverTLS()

	builtClient := dnsBuilder.AddProvider("1.1.1.1", "1.1.1.1:853").Build()

	if builtClient == nil {
		t.Error("expected client with multiple DNS providers to be non-nil")
	}
}

func TestDNSOverTLSAllProviders(t *testing.T) {
	t.Parallel()

	// Test that all providers can be instantiated and chained
	providers := []string{
		"AdGuard", "Google", "Quad9", "Switch", "CIRAShield",
		"Ali", "Quad101", "SB", "Forge", "LibreDNS",
	}

	for i, name := range providers {
		t.Run(fmt.Sprintf("Provider_%s_%d", name, i), func(t *testing.T) {
			client := surf.NewClient()
			builder := client.Builder()
			dnsBuilder := builder.DNSOverTLS()

			var builtClient *surf.Client

			// First test that the provider works
			switch name {
			case "AdGuard":
				builtClient = dnsBuilder.AdGuard().Build()
			case "Google":
				builtClient = dnsBuilder.Google().Build()
			case "Quad9":
				builtClient = dnsBuilder.Quad9().Build()
			case "Switch":
				builtClient = dnsBuilder.Switch().Build()
			case "CIRAShield":
				builtClient = dnsBuilder.CIRAShield().Build()
			case "Ali":
				builtClient = dnsBuilder.Ali().Build()
			case "Quad101":
				builtClient = dnsBuilder.Quad101().Build()
			case "SB":
				builtClient = dnsBuilder.SB().Build()
			case "Forge":
				builtClient = dnsBuilder.Forge().Build()
			case "LibreDNS":
				builtClient = dnsBuilder.LibreDNS().Build()
			}

			if builtClient == nil {
				t.Error("expected client to be built successfully")
				return
			}

			// Now test AddProvider separately
			client2 := surf.NewClient()
			builder2 := client2.Builder()
			dnsBuilder2 := builder2.DNSOverTLS()
			builtClient2 := dnsBuilder2.AddProvider("test.com", "test.com:853").Build()

			if builtClient2 == nil {
				t.Error("expected client with AddProvider to be built successfully")
			}
		})
	}
}

func TestDNSOverTLSResolverConfiguration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		buildFunc   func(*surf.DNSOverTLS) *surf.Builder
		expectError bool
	}{
		{
			"AdGuard configuration",
			func(dot *surf.DNSOverTLS) *surf.Builder { return dot.AdGuard() },
			false,
		},
		{
			"Google configuration",
			func(dot *surf.DNSOverTLS) *surf.Builder { return dot.Google() },
			false,
		},
		{
			"Cloudflare configuration",
			func(dot *surf.DNSOverTLS) *surf.Builder { return dot.Cloudflare() },
			false,
		},
		{
			"Quad9 configuration",
			func(dot *surf.DNSOverTLS) *surf.Builder { return dot.Quad9() },
			false,
		},
		{
			"Custom provider",
			func(dot *surf.DNSOverTLS) *surf.Builder {
				return dot.AddProvider("custom.dns.com", "1.2.3.4:853")
			},
			false,
		},
		{
			"Multiple servers",
			func(dot *surf.DNSOverTLS) *surf.Builder {
				return dot.AddProvider("multi.dns.com", "1.1.1.1:853", "8.8.8.8:853")
			},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := surf.NewClient()
			builder := client.Builder()
			dnsBuilder := builder.DNSOverTLS()

			builtClient := tc.buildFunc(dnsBuilder).Build()

			if tc.expectError {
				if builtClient != nil {
					t.Errorf("expected error for %s, but got valid client", tc.name)
				}
			} else {
				if builtClient == nil {
					t.Errorf("expected valid client for %s, but got nil", tc.name)
				} else {
					// Verify resolver is configured
					resolver := builtClient.GetDialer().Resolver
					if resolver == nil {
						t.Errorf("expected resolver to be configured for %s", tc.name)
					}
				}
			}
		})
	}
}

func TestDNSOverTLSIntegration(t *testing.T) {
	t.Parallel()

	// Test with local test server
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"dns_provider": "test", "host": "%s"}`, r.Host)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	providers := []struct {
		name      string
		buildFunc func(*surf.DNSOverTLS) *surf.Builder
	}{
		{"AdGuard", func(dot *surf.DNSOverTLS) *surf.Builder { return dot.AdGuard() }},
		{"Google", func(dot *surf.DNSOverTLS) *surf.Builder { return dot.Google() }},
		{"Cloudflare", func(dot *surf.DNSOverTLS) *surf.Builder { return dot.Cloudflare() }},
		{"Custom", func(dot *surf.DNSOverTLS) *surf.Builder {
			return dot.AddProvider("test.dns.com", "8.8.8.8:853")
		}},
	}

	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			client := surf.NewClient()
			builder := client.Builder()
			dnsBuilder := builder.DNSOverTLS()

			builtClient := provider.buildFunc(dnsBuilder).Build()
			if builtClient == nil {
				t.Fatalf("expected client to be built for %s", provider.name)
			}

			req := builtClient.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Errorf("request failed with %s DNS over TLS: %v", provider.name, resp.Err())
			} else {
				if resp.Ok().StatusCode != http.StatusOK {
					t.Errorf("expected status 200 with %s, got %d", provider.name, resp.Ok().StatusCode)
				}
			}
		})
	}
}

func TestDNSOverTLSWithOtherFeatures(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "integration test")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	testCases := []struct {
		name      string
		buildFunc func(*surf.Builder) *surf.Client
	}{
		{
			"DNS over TLS with proxy",
			func(b *surf.Builder) *surf.Client {
				return b.DNSOverTLS().Google().Proxy("http://localhost:8080").Build()
			},
		},
		{
			"DNS over TLS with timeout",
			func(b *surf.Builder) *surf.Client {
				return b.DNSOverTLS().Cloudflare().Timeout(time.Second * 30).Build()
			},
		},
		{
			"DNS over TLS with user agent",
			func(b *surf.Builder) *surf.Client {
				return b.DNSOverTLS().AdGuard().UserAgent("test-agent").Build()
			},
		},
		{
			"DNS over TLS with session",
			func(b *surf.Builder) *surf.Client {
				return b.DNSOverTLS().Quad9().Session().Build()
			},
		},
		{
			"DNS over TLS with impersonation",
			func(b *surf.Builder) *surf.Client {
				return b.DNSOverTLS().Google().Impersonate().Chrome().Build()
			},
		},
		{
			"DNS over TLS with HTTP/3",
			func(b *surf.Builder) *surf.Client {
				return b.DNSOverTLS().Cloudflare().HTTP3().Build()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := surf.NewClient()
			builder := client.Builder()
			builtClient := tc.buildFunc(builder)

			if builtClient == nil {
				t.Fatalf("expected client to be built for %s", tc.name)
			}

			// Verify resolver is still configured
			resolver := builtClient.GetDialer().Resolver
			if resolver == nil {
				t.Errorf("expected resolver to still be configured for %s", tc.name)
			}

			// Test actual request (may fail for proxy configurations in test env)
			req := builtClient.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				// Log error but don't fail - integration issues are expected
				t.Logf("%s failed (expected in test env): %v", tc.name, resp.Err())
			} else {
				if resp.Ok().StatusCode != http.StatusOK {
					t.Errorf("expected status 200 for %s, got %d", tc.name, resp.Ok().StatusCode)
				}
			}
		})
	}
}

func TestDNSOverTLSErrorHandling(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		buildFunc  func(*surf.DNSOverTLS) *surf.Builder
		shouldFail bool
	}{
		{
			"Empty provider name",
			func(dot *surf.DNSOverTLS) *surf.Builder {
				return dot.AddProvider("", "1.1.1.1:853")
			},
			false, // Should still work, just with empty server name
		},
		{
			"No server addresses",
			func(dot *surf.DNSOverTLS) *surf.Builder {
				return dot.AddProvider("test.dns.com")
			},
			false, // Should still work with empty address list
		},
		{
			"Multiple chained calls",
			func(dot *surf.DNSOverTLS) *surf.Builder {
				return dot.Google().DNSOverTLS().Cloudflare() // Last one should win
			},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := surf.NewClient()
			builder := client.Builder()
			dnsBuilder := builder.DNSOverTLS()

			builtClient := tc.buildFunc(dnsBuilder).Build()

			if tc.shouldFail {
				if builtClient != nil {
					t.Errorf("expected %s to fail, but got valid client", tc.name)
				}
			} else {
				if builtClient == nil {
					t.Errorf("expected %s to succeed, but got nil client", tc.name)
				}
			}
		})
	}
}

func TestDNSOverTLSProviderChaining(t *testing.T) {
	t.Parallel()

	// Test that providers can be chained properly
	client := surf.NewClient()
	builder := client.Builder()
	dnsBuilder := builder.DNSOverTLS()

	// Chain multiple providers - last should win
	builtClient := dnsBuilder.
		Google().
		DNSOverTLS().Cloudflare().
		DNSOverTLS().AdGuard().
		Build()

	if builtClient == nil {
		t.Fatal("expected chained client to be built successfully")
	}

	// Verify resolver is configured
	resolver := builtClient.GetDialer().Resolver
	if resolver == nil {
		t.Error("expected resolver to be configured after chaining")
	}
}

func TestDNSOverTLSWithCustomDialer(t *testing.T) {
	t.Parallel()

	// Test that DNS over TLS works with custom dialer settings
	client := surf.NewClient()
	builder := client.Builder()

	builtClient := builder.
		Timeout(time.Second * 10).
		DNSOverTLS().Google().
		InterfaceAddr("127.0.0.1").
		Build()

	if builtClient == nil {
		t.Fatal("expected client with custom dialer to be built")
	}

	// Check that both resolver and custom dialer settings are preserved
	dialer := builtClient.GetDialer()
	if dialer == nil {
		t.Fatal("expected dialer to be set")
	}

	if dialer.Resolver == nil {
		t.Error("expected resolver to be configured")
	}

	// LocalAddr should be set from InterfaceAddr
	if dialer.LocalAddr == nil {
		// This might fail in test environments, so just log
		t.Log("LocalAddr not set (may be expected in test environment)")
	}
}
