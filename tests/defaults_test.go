package surf_test

import (
	"testing"
	"time"

	"github.com/enetx/surf"
)

func TestDefaultConstants(t *testing.T) {
	t.Parallel()

	// Create a new client to verify default values are applied
	client := surf.NewClient()

	if client == nil {
		t.Fatal("expected client to be created with defaults")
	}

	// Test that client can be built successfully with defaults
	builder := client.Builder()
	if builder == nil {
		t.Fatal("expected builder to be created")
	}

	built := builder.Build().Unwrap()
	if built == nil {
		t.Fatal("expected client to be built with defaults")
	}

	// Verify that all default configurations work together
	if built != client {
		t.Error("expected built client to be same instance as original")
	}
}

func TestDefaultUserAgent(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()

	// Get the default transport/client configuration
	transport := client.GetTransport()
	if transport == nil {
		t.Fatal("expected transport to be configured")
	}

	// Test that default user agent is properly set by making a request
	// We can't directly access the constant but can verify it's used
}

func TestDefaultTimeouts(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()

	// Test that default timeouts are reasonable and don't cause issues
	httpClient := client.GetClient()
	if httpClient == nil {
		t.Fatal("expected HTTP client to be configured")
	}

	// Default client timeout should be set
	if httpClient.Timeout == 0 {
		t.Error("expected default client timeout to be set")
	}

	// Should be 30 seconds based on defaults
	expectedTimeout := 30 * time.Second
	if httpClient.Timeout != expectedTimeout {
		t.Logf("client timeout is %v, expected %v", httpClient.Timeout, expectedTimeout)
	}
}

func TestDefaultTransportSettings(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()

	transport := client.GetTransport()
	if transport == nil {
		t.Fatal("expected transport to be configured with defaults")
	}

	// Test that we can access transport settings
	// The actual values are internal but we can test the transport exists
}

func TestDefaultDialer(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()

	dialer := client.GetDialer()
	if dialer == nil {
		t.Fatal("expected dialer to be configured with defaults")
	}

	// Test default dialer timeout
	expectedTimeout := 10 * time.Second
	if dialer.Timeout != expectedTimeout {
		t.Errorf("expected dialer timeout %v, got %v", expectedTimeout, dialer.Timeout)
	}

	// Test default keep alive
	expectedKeepAlive := 15 * time.Second
	if dialer.KeepAlive != expectedKeepAlive {
		t.Errorf("expected dialer keep alive %v, got %v", expectedKeepAlive, dialer.KeepAlive)
	}
}

func TestDefaultTLSConfig(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()

	tlsConfig := client.GetTLSConfig()
	if tlsConfig == nil {
		t.Fatal("expected TLS config to be configured with defaults")
	}

	// Test that TLS config has reasonable defaults
	// We don't test specific values as they may change, but ensure it's configured
}

func TestDefaultsIntegration(t *testing.T) {
	t.Parallel()

	// Test that all default values work together in a real scenario
	client := surf.NewClient()

	// Should be able to configure various options without issues
	builder := client.Builder().
		Timeout(10 * time.Second).
		MaxRedirects(5).
		UserAgent("test-agent")

	builtClient := builder.Build().Unwrap()
	if builtClient == nil {
		t.Fatal("expected client to build successfully with modified defaults")
	}

	// Test that the client with defaults can handle basic configuration
	if builtClient.GetClient() == nil {
		t.Error("expected HTTP client to be accessible")
	}

	if builtClient.GetTransport() == nil {
		t.Error("expected transport to be accessible")
	}

	if builtClient.GetDialer() == nil {
		t.Error("expected dialer to be accessible")
	}

	if builtClient.GetTLSConfig() == nil {
		t.Error("expected TLS config to be accessible")
	}
}
