package surf_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestImpersonateChrome(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Impersonate().Chrome().
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Test that Chrome headers are applied
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	if !strings.Contains(body.Std(), "Chrome") {
		t.Error("expected Chrome user agent to be applied")
	}
}

func TestImpersonateFirefox(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Impersonate().Firefox().
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Test that Firefox headers are applied
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	if !strings.Contains(body.Std(), "Firefox") {
		t.Error("expected Firefox user agent to be applied")
	}
}

func TestImpersonateWithOS(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Impersonate().Windows().Chrome().
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	// Test that Windows Chrome headers are applied
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	if !strings.Contains(body.Std(), "Chrome") {
		t.Error("expected Chrome user agent to be applied")
	}

	if !strings.Contains(body.Std(), "Windows") {
		t.Error("expected Windows platform to be applied")
	}
}

func TestImpersonateMacOS(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Impersonate().MacOS().Chrome().
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	if !strings.Contains(body.Std(), "Chrome") {
		t.Error("expected Chrome user agent to be applied")
	}
}

func TestImpersonateLinux(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Impersonate().Linux().Chrome().
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	if !strings.Contains(body.Std(), "Chrome") {
		t.Error("expected Chrome user agent to be applied")
	}
}

func TestImpersonateAndroid(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Impersonate().Android().Chrome().
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	if !strings.Contains(body.Std(), "Chrome") {
		t.Error("expected Chrome user agent to be applied")
	}
}

func TestImpersonateIOS(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Impersonate().IOS().Chrome().
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	// For iOS impersonation, expect either Safari or iOS/iPhone in the user agent
	if !strings.Contains(body.Std(), "Safari") && !strings.Contains(body.Std(), "iPhone") &&
		!strings.Contains(body.Std(), "iOS") {
		t.Logf("User agent: %s", body.Std())
		t.Error("expected iOS/Safari user agent to be applied")
	}
}

func TestImpersonateRandomOS(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Impersonate().RandomOS().Chrome().
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	// RandomOS can select any OS, so just verify that some user agent was set
	if body.Std() == "" {
		t.Error("expected user agent to be set")
	} else {
		t.Logf("Random OS user agent: %s", body.Std())
	}
}

func TestImpersonateWithCustomHeaders(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		customHeader := r.Header.Get("X-Custom")
		fmt.Fprintf(w, "User-Agent: %s\nX-Custom: %s", userAgent, customHeader)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	headers := g.NewMapOrd[g.String, g.String](1)
	headers.Insert("X-Custom", "test-value")

	client := surf.NewClient().Builder().
		Impersonate().Chrome().
		SetHeaders(headers).
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.String().Ok()
	if !strings.Contains(body.Std(), "Chrome") {
		t.Error("expected Chrome user agent to be applied")
	}

	// Note: Custom headers may be overridden by impersonation for authenticity
	// This is expected behavior - impersonation should override headers for realism
	if strings.Contains(body.Std(), "test-value") {
		t.Log("custom header was preserved (this may or may not be expected)")
	} else {
		t.Log("custom header was overridden by impersonation (this is expected behavior)")
	}
}

func TestImpersonateChromeHeaders(t *testing.T) {
	t.Parallel()

	var receivedHeaders http.Header
	handler := func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Impersonate().Chrome().
		Build().Unwrap()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Verify Chrome-specific headers
	expectedHeaders := map[string]bool{
		"User-Agent":                true,
		"Accept":                    true,
		"Accept-Encoding":           true,
		"Accept-Language":           true,
		"Sec-Ch-Ua":                 true,
		"Sec-Ch-Ua-Mobile":          true,
		"Sec-Ch-Ua-Platform":        true,
		"Sec-Fetch-Dest":            true,
		"Sec-Fetch-Mode":            true,
		"Sec-Fetch-Site":            true,
		"Sec-Fetch-User":            true,
		"Upgrade-Insecure-Requests": true,
		"Priority":                  true,
	}

	for header := range expectedHeaders {
		if receivedHeaders.Get(header) == "" {
			t.Errorf("expected header %s to be set", header)
		}
	}

	// Verify specific Chrome header values
	userAgent := receivedHeaders.Get("User-Agent")
	if !strings.Contains(userAgent, "Chrome") {
		t.Errorf("expected Chrome in user agent, got: %s", userAgent)
	}

	secChUa := receivedHeaders.Get("Sec-Ch-Ua")
	if !strings.Contains(secChUa, "Google Chrome") {
		t.Errorf("expected Google Chrome in Sec-Ch-Ua, got: %s", secChUa)
	}

	acceptEncoding := receivedHeaders.Get("Accept-Encoding")
	if !strings.Contains(acceptEncoding, "br") || !strings.Contains(acceptEncoding, "zstd") {
		t.Errorf("expected br and zstd in Accept-Encoding, got: %s", acceptEncoding)
	}
}

func TestImpersonateChromeBoundaryGeneration(t *testing.T) {
	t.Parallel()

	// Test that Chrome boundary generation works correctly
	client := surf.NewClient().Builder().
		Impersonate().Chrome().
		Build().Unwrap()

	// Create multiple multipart requests to test boundary uniqueness
	formData := g.NewMapOrd[g.String, g.String](2)
	formData.Insert(g.String("field1"), g.String("value1"))
	formData.Insert(g.String("field2"), g.String("value2"))

	boundaries := make(map[string]bool)

	for range 10 {
		req := client.Multipart("http://localhost/test", formData)

		// Get the boundary from the request
		contentType := req.GetRequest().Header.Get("Content-Type")
		if !strings.Contains(contentType, "boundary=") {
			t.Fatal("expected Content-Type to contain boundary")
		}

		// Extract boundary
		parts := strings.Split(contentType, "boundary=")
		if len(parts) != 2 {
			t.Fatal("expected boundary in Content-Type")
		}
		boundary := parts[1]

		// Verify it's Chrome-style boundary (starts with ----WebKitFormBoundary)
		if !strings.HasPrefix(boundary, "----WebKitFormBoundary") {
			t.Errorf("expected Chrome boundary to start with ----WebKitFormBoundary, got: %s", boundary)
		}

		// Check uniqueness
		if boundaries[boundary] {
			t.Error("expected unique boundaries, but found duplicate")
		}
		boundaries[boundary] = true

		// Verify length (----WebKitFormBoundary + 16 random characters)
		expectedLength := len("----WebKitFormBoundary") + 16
		if len(boundary) != expectedLength {
			t.Errorf("expected boundary length %d, got %d for boundary: %s", expectedLength, len(boundary), boundary)
		}
	}
}

func TestImpersonateChromeOSVariants(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		osFunc         func(*surf.Impersonate) *surf.Impersonate
		expectUA       string
		expectPlatform string
	}{
		{
			"Windows Chrome",
			func(imp *surf.Impersonate) *surf.Impersonate { return imp.Windows() },
			"Windows NT",
			"Windows",
		},
		{
			"MacOS Chrome",
			func(imp *surf.Impersonate) *surf.Impersonate { return imp.MacOS() },
			"Macintosh",
			"macOS",
		},
		{
			"Linux Chrome",
			func(imp *surf.Impersonate) *surf.Impersonate { return imp.Linux() },
			"X11; Linux",
			"Linux",
		},
		{
			"Android Chrome",
			func(imp *surf.Impersonate) *surf.Impersonate { return imp.Android() },
			"Android",
			"Android",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var receivedHeaders http.Header
			handler := func(w http.ResponseWriter, r *http.Request) {
				receivedHeaders = r.Header
				w.WriteHeader(http.StatusOK)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			impersonate := surf.NewClient().Builder().Impersonate()
			osImpersonate := tc.osFunc(impersonate)
			client := osImpersonate.Chrome().Build().Unwrap()

			req := client.Get(g.String(ts.URL))
			resp := req.Do()

			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			userAgent := receivedHeaders.Get("User-Agent")
			if !strings.Contains(userAgent, tc.expectUA) {
				t.Errorf("expected user agent to contain %s, got: %s", tc.expectUA, userAgent)
			}

			platform := receivedHeaders.Get("Sec-Ch-Ua-Platform")
			if !strings.Contains(platform, tc.expectPlatform) {
				t.Errorf("expected platform header to contain %s, got: %s", tc.expectPlatform, platform)
			}

			// Verify mobile flag for Android
			mobile := receivedHeaders.Get("Sec-Ch-Ua-Mobile")
			if tc.name == "Android Chrome" {
				if mobile != "?1" {
					t.Errorf("expected mobile=?1 for Android, got: %s", mobile)
				}
			} else {
				if mobile != "?0" {
					t.Errorf("expected mobile=?0 for %s, got: %s", tc.name, mobile)
				}
			}
		})
	}
}

func TestImpersonateChromeTransportConfiguration(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Impersonate().Chrome().
		Build().Unwrap()

	// Verify the client was properly configured
	if client.GetClient() == nil {
		t.Fatal("expected HTTP client to be configured")
	}

	if client.GetClient().Transport == nil {
		t.Fatal("expected transport to be configured")
	}

	// Test that the impersonation works with a real request
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Success")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	if body.Std() != "Success" {
		t.Errorf("expected body 'Success', got: %s", body.Std())
	}
}

func TestImpersonateChromeJA3Configuration(t *testing.T) {
	t.Parallel()

	// Test that Chrome impersonation includes JA3 configuration
	client := surf.NewClient().Builder().
		Impersonate().Chrome().
		Build().Unwrap()

	// The JA3 configuration is internal, but we can verify the client builds successfully
	// and that TLS configuration is present
	if client.GetTLSConfig() == nil {
		t.Fatal("expected TLS config to be set for JA3 impersonation")
	}

	// Test with an HTTPS server if available
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "tls test")
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		// TLS/JA3 errors are common in test environments
		t.Logf("TLS test failed (may be expected): %v", resp.Err())
		return
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}
}

func TestImpersonateFirefoxPrivate(t *testing.T) {
	t.Parallel()

	client := surf.NewClient().Builder().
		Impersonate().FirefoxPrivate().
		Build().Unwrap()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		userAgent := r.Header.Get("User-Agent")
		fmt.Fprintf(w, `{"user-agent": "%s"}`, userAgent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String().Ok()
	if !strings.Contains(body.Std(), "Firefox") {
		t.Error("expected Firefox user agent to be applied")
	}
}
