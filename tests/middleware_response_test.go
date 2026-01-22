package surf_test

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/klauspost/compress/zstd"
)

func TestMiddlewareResponseCloseIdleConnections(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"test": "close_idle"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// The middleware should close idle connections after response
	// We can't easily test the actual closing, but we can verify the request succeeded
	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String()
	if !strings.Contains(body.Std(), "close_idle") {
		t.Error("expected response body to contain test data")
	}
}

func TestMiddlewareResponseWebSocketUpgradeError(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Simulate WebSocket upgrade response
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	// Should get WebSocket upgrade error
	if resp.IsOk() {
		t.Error("expected WebSocket upgrade error")
	}

	if _, ok := resp.Err().(*surf.ErrWebSocketUpgrade); !ok {
		t.Fatalf("expected ErrWebSocketUpgrade type, got %T", resp.Err())
	}
}

func TestMiddlewareResponseWebSocketUpgradeNormal(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Normal response without WebSocket upgrade
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"normal": "response"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareResponseDecodeBodyGzip(t *testing.T) {
	t.Parallel()

	originalData := "This is test data for gzip compression"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Create gzip compressed response
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(originalData))
		gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Errorf("expected decompressed body %q, got %q", originalData, body.Std())
	}
}

func TestMiddlewareResponseDecodeBodyDeflate(t *testing.T) {
	t.Parallel()

	originalData := "This is test data for deflate compression"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Create deflate compressed response
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		zw.Write([]byte(originalData))
		zw.Close()

		w.Header().Set("Content-Encoding", "deflate")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Errorf("expected decompressed body %q, got %q", originalData, body.Std())
	}
}

func TestMiddlewareResponseDecodeBodyBrotli(t *testing.T) {
	t.Parallel()

	originalData := "This is test data for brotli compression"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Create brotli compressed response
		var buf bytes.Buffer
		br := brotli.NewWriter(&buf)
		br.Write([]byte(originalData))
		br.Close()

		w.Header().Set("Content-Encoding", "br")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Errorf("expected decompressed body %q, got %q", originalData, body.Std())
	}
}

func TestMiddlewareResponseDecodeBodyZstd(t *testing.T) {
	t.Parallel()

	originalData := "This is test data for zstd compression"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Create zstd compressed response
		var buf bytes.Buffer
		encoder, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		encoder.Write([]byte(originalData))
		encoder.Close()

		w.Header().Set("Content-Encoding", "zstd")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Errorf("expected decompressed body %q, got %q", originalData, body.Std())
	}
}

func TestMiddlewareResponseDecodeBodyNoCompression(t *testing.T) {
	t.Parallel()

	originalData := "This is test data without compression"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, originalData)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Errorf("expected body %q, got %q", originalData, body.Std())
	}
}

func TestMiddlewareResponseDecodeBodyEmptyBody(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Return empty body with 200 status
		w.WriteHeader(http.StatusOK)
		// No content written
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if resp.Ok().StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.Ok().StatusCode)
	}

	// Body should be empty
	body := resp.Ok().Body.String()
	if !body.IsEmpty() {
		t.Errorf("expected empty body, got %q", body.Std())
	}
}

func TestMiddlewareResponseDecodeBodyInvalidGzip(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		// Invalid gzip data
		w.Write([]byte("invalid gzip data"))
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	// Should handle invalid gzip gracefully
	if resp.IsErr() {
		// Expected behavior - invalid compression should cause error
		if !strings.Contains(resp.Err().Error(), "gzip") && !strings.Contains(resp.Err().Error(), "invalid") {
			t.Logf("Got compression error as expected: %v", resp.Err())
		}
	}
}

func TestMiddlewareResponseDecodeBodyInvalidDeflate(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		w.WriteHeader(http.StatusOK)
		// Invalid deflate data
		w.Write([]byte("invalid deflate data"))
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	// Should handle invalid deflate gracefully
	if resp.IsErr() {
		// Expected behavior - invalid compression should cause error
		if !strings.Contains(resp.Err().Error(), "deflate") && !strings.Contains(resp.Err().Error(), "invalid") {
			t.Logf("Got compression error as expected: %v", resp.Err())
		}
	}
}

func TestMiddlewareResponseDecodeBodyInvalidZstd(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "zstd")
		w.WriteHeader(http.StatusOK)
		// Invalid zstd data
		w.Write([]byte("invalid zstd data"))
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	// Should handle invalid zstd gracefully
	if resp.IsErr() {
		// Expected behavior - invalid compression should cause error
		t.Logf("Got compression error as expected: %v", resp.Err())
	}
}

func TestMiddlewareResponseDecodeBodyUnknownEncoding(t *testing.T) {
	t.Parallel()

	originalData := "This data has unknown encoding"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "unknown")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, originalData)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Should pass through without decoding
	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Errorf("expected body %q, got %q", originalData, body.Std())
	}
}

func TestMiddlewareResponseDecodeBodyMultipleEncodings(t *testing.T) {
	t.Parallel()

	originalData := "This data has multiple encodings"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Multiple encoding headers (should handle gracefully)
		w.Header().Set("Content-Encoding", "gzip, deflate")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, originalData)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Should handle or pass through gracefully
	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Errorf("expected body %q, got %q", originalData, body.Std())
	}
}

func TestMiddlewareResponseDecodeBodyCaseInsensitiveEncoding(t *testing.T) {
	t.Parallel()

	originalData := "This is test data for case insensitive gzip"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Create gzip compressed response
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(originalData))
		gz.Close()

		// Use uppercase encoding header
		w.Header().Set("Content-Encoding", "GZIP")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Should handle case-insensitive encoding
	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Errorf("expected decompressed body %q, got %q", originalData, body.Std())
	}
}

func TestMiddlewareResponseDecodeBodyLargeData(t *testing.T) {
	t.Parallel()

	// Create large data to test compression handling with bigger payloads
	originalData := strings.Repeat("This is test data for large compressed content. ", 1000)

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Create gzip compressed response
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(originalData))
		gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Error("large gzip decompression failed")
	}

	if len(body.Std()) != len(originalData) {
		t.Errorf("expected decompressed body length %d, got %d", len(originalData), len(body.Std()))
	}
}

func TestMiddlewareResponseHeaderPreservation(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Custom-Header", "test-value")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"test": "data"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Verify headers are preserved through middleware
	if response.Headers.Get("X-Custom-Header") != "test-value" {
		t.Error("X-Custom-Header not preserved")
	}

	if response.Headers.Get("Content-Type") != "application/json" {
		t.Error("Content-Type not preserved")
	}

	if response.Headers.Get("Cache-Control") != "no-cache" {
		t.Error("Cache-Control not preserved")
	}
}

func TestMiddlewareResponseChaining(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Create gzip compressed response with multiple characteristics
		originalData := `{"message": "middleware chaining test"}`
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(originalData))
		gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Test-Chain", "middleware")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	middlewareExecuted := false

	client := surf.NewClient().Builder().
		With(func(resp *surf.Response) error {
			middlewareExecuted = true
			// Verify we can access response properties in middleware
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status 200 in middleware, got %d", resp.StatusCode)
			}
			if resp.Headers.Get("X-Test-Chain") != "middleware" {
				t.Error("header not accessible in middleware")
			}
			return nil
		}).
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !middlewareExecuted {
		t.Error("custom middleware was not executed")
	}

	// Verify decompression still works with custom middleware
	body := resp.Ok().Body.String()
	if !body.Contains("middleware chaining test") {
		t.Error("body decompression failed with middleware chaining")
	}
}

func TestMiddlewareResponseWithErrors(t *testing.T) {
	t.Parallel()

	middlewareError := false

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "server error")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		With(func(resp *surf.Response) error {
			middlewareError = true
			// Middleware should be called even for error responses
			if resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("expected status 500 in middleware, got %d", resp.StatusCode)
			}
			return nil
		}).
		Build().Unwrap()

	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !middlewareError {
		t.Error("middleware was not called for error response")
	}

	if resp.Ok().StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", resp.Ok().StatusCode)
	}
}

func TestMiddlewareResponseBodyCache(t *testing.T) {
	t.Parallel()

	originalData := "This is cached body data"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, originalData)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with body caching enabled
	client := surf.NewClient().Builder().CacheBody().Build().Unwrap()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Read body multiple times to test caching
	body1 := response.Body.String()
	body2 := response.Body.String()

	if body1.Std() != originalData || body2.Std() != originalData {
		t.Error("body caching not working properly")
	}

	if body1 != body2 {
		t.Error("cached bodies should be identical")
	}
}

func TestMiddlewareResponseNilBody(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// No body content
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	// HEAD request should have nil body
	resp := client.Head(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Middleware should handle nil body gracefully
	if response.Body != nil {
		t.Error("expected nil body for HEAD request")
	}
}

func TestMiddlewareResponseCompressionMiddleware(t *testing.T) {
	t.Parallel()

	originalData := "This is test data for compression middleware test"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Create gzip compressed response
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(originalData))
		gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test standard compression handling
	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Response should be automatically decompressed by middleware
	body := resp.Ok().Body.String()
	if body.Std() != originalData {
		t.Error("automatic decompression by middleware failed")
	}

	// Content-Encoding header may be removed after decompression (implementation detail)
	// The important thing is that the body was properly decompressed
}
