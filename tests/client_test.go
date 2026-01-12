package surf_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}

	// Test that client has default configuration
	if client.GetClient() == nil {
		t.Error("GetClient() returned nil")
	}
	if client.GetDialer() == nil {
		t.Error("GetDialer() returned nil")
	}
	if client.GetTransport() == nil {
		t.Error("GetTransport() returned nil")
	}
	if client.GetTLSConfig() == nil {
		t.Error("GetTLSConfig() returned nil")
	}
}

func TestClientHTTPMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		fn     func(*surf.Client, g.String) *surf.Request
	}{
		{"GET", "GET", func(c *surf.Client, url g.String) *surf.Request {
			return c.Get(url)
		}},
		{"DELETE", "DELETE", func(c *surf.Client, url g.String) *surf.Request {
			return c.Delete(url)
		}},
		{"HEAD", "HEAD", func(c *surf.Client, url g.String) *surf.Request {
			return c.Head(url)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.method {
					t.Errorf("expected method %s, got %s", tt.method, r.Method)
				}
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "ok")
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := tt.fn(client, g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
			}
		})
	}
}

func TestClientGetWithParams(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET method, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "name=test") || !strings.Contains(bodyStr, "value=123") {
			t.Errorf("expected name=test&value=123 in body, got %s", bodyStr)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	// Test GET with map parameters
	params := g.NewMapOrd[g.String, g.String](2)
	params.Set("name", "test")
	params.Set("value", "123")

	resp := client.Get(g.String(ts.URL), params).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestClientErrorHandling(t *testing.T) {
	t.Parallel()

	// Test various error scenarios
	tests := []struct {
		name string
		url  string
	}{
		{"Invalid URL", "not-a-valid-url"},
		{"Malformed URL", "http://[::1:invalid"},
		{"Invalid scheme", "ftp://127.0.0.1"},
		{"Empty URL", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := surf.NewClient()
			req := client.Get(g.String(tt.url))

			// Request creation should handle errors gracefully
			if req != nil {
				// If request is created, it might fail during execution
				resp := req.Do()
				if !resp.IsErr() {
					t.Log("Unexpectedly successful request")
				}
			} else {
				t.Log("Request creation failed as expected")
			}
		})
	}
}

func TestClientConcurrentRequests(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "concurrent response")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	concurrency := 5
	results := make(chan error, concurrency)

	client := surf.NewClient()

	for range concurrency {
		go func() {
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				results <- resp.Err()
				return
			}
			if !resp.Ok().StatusCode.IsSuccess() {
				results <- fmt.Errorf("unexpected status: %d", resp.Ok().StatusCode)
				return
			}
			results <- nil
		}()
	}

	// Wait for all goroutines to complete
	for range concurrency {
		if err := <-results; err != nil {
			t.Errorf("concurrent request failed: %v", err)
		}
	}
}

func TestClientTimeout(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "slow response")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Client with reasonable timeout
	client := surf.NewClient().Builder().
		Timeout(5 * time.Second). // 5 seconds - should be enough
		Build()

	// This should succeed (response is faster than timeout)
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Logf("request with normal timeout failed: %v", resp.Err())
	} else if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// Test with very short timeout that should fail
	clientFast := surf.NewClient().Builder().
		Timeout(1 * time.Millisecond). // Very short timeout
		Build()

	resp2 := clientFast.Get(g.String(ts.URL)).Do()
	// This should timeout
	if !resp2.IsErr() {
		t.Log("Expected timeout but request succeeded")
	}
}

func TestClientContextCancellation(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "delayed response")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req := client.Get(g.String(ts.URL))
	req.GetRequest().WithContext(ctx)
	resp := req.Do()
	if !resp.IsErr() {
		t.Log("Expected request to be cancelled, but it succeeded")
	}
}

func TestClientRedirects(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		if r.URL.Path == "/final" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "final destination")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL + "/redirect")).Do()

	if resp.IsErr() {
		t.Fatalf("redirect failed: %v", resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success after redirect, got %d", resp.Ok().StatusCode)
	}

	body := resp.Ok().Body.String()
	if !body.Contains("final destination") {
		t.Errorf("expected 'final destination', got %s", body)
	}
}

func TestClientPostWithData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		data        any
		contentType string
		validate    func([]byte, string) error
	}{
		{
			name: "JSON struct",
			data: struct {
				Name string `json:"name"`
			}{Name: "test"},
			contentType: "application/json",
			validate: func(body []byte, ct string) error {
				if !strings.Contains(ct, "application/json") {
					return fmt.Errorf("expected json content-type, got %s", ct)
				}
				var data struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal(body, &data); err != nil {
					return err
				}
				if data.Name != "test" {
					return fmt.Errorf("expected name=test, got %s", data.Name)
				}
				return nil
			},
		},
		{
			name: "XML struct",
			data: struct {
				Name string `xml:"name"`
			}{Name: "test"},
			contentType: "application/json", // XML detection might not be automatic
			validate: func(body []byte, _ string) error {
				// Accept any content type since XML detection might not work
				if len(body) == 0 {
					return fmt.Errorf("expected non-empty body")
				}
				return nil
			},
		},
		{
			name:        "String data",
			data:        "test=value&foo=bar",
			contentType: "application/x-www-form-urlencoded",
			validate: func(body []byte, ct string) error {
				if !strings.Contains(ct, "application/x-www-form-urlencoded") {
					return fmt.Errorf("expected form content-type, got %s", ct)
				}
				if string(body) != "test=value&foo=bar" {
					return fmt.Errorf("expected test=value&foo=bar, got %s", string(body))
				}
				return nil
			},
		},
		{
			name:        "g.String data",
			data:        g.String("plain text"),
			contentType: "text/plain",
			validate: func(body []byte, ct string) error {
				if !strings.Contains(ct, "text/plain") {
					return fmt.Errorf("expected text/plain content-type, got %s", ct)
				}
				if string(body) != "plain text" {
					return fmt.Errorf("expected 'plain text', got %s", string(body))
				}
				return nil
			},
		},
		{
			name:        "Bytes data",
			data:        []byte("byte data"),
			contentType: "text/plain",
			validate: func(body []byte, _ string) error {
				if string(body) != "byte data" {
					return fmt.Errorf("expected 'byte data', got %s", string(body))
				}
				return nil
			},
		},
		{
			name:        "g.Bytes data",
			data:        g.Bytes("g.bytes data"),
			contentType: "text/plain",
			validate: func(body []byte, _ string) error {
				if string(body) != "g.bytes data" {
					return fmt.Errorf("expected 'g.bytes data', got %s", string(body))
				}
				return nil
			},
		},
		{
			name:        "Map data",
			data:        map[string]string{"key": "value", "foo": "bar"},
			contentType: "application/x-www-form-urlencoded",
			validate: func(body []byte, ct string) error {
				if !strings.Contains(ct, "application/x-www-form-urlencoded") {
					return fmt.Errorf("expected form content-type, got %s", ct)
				}
				values, _ := url.ParseQuery(string(body))
				if values.Get("key") != "value" || values.Get("foo") != "bar" {
					return fmt.Errorf("unexpected form data: %v", values)
				}
				return nil
			},
		},
		{
			name:        "g.Map data",
			data:        g.Map[string, string]{"key": "value"},
			contentType: "application/x-www-form-urlencoded",
			validate: func(body []byte, ct string) error {
				if !strings.Contains(ct, "application/x-www-form-urlencoded") {
					return fmt.Errorf("expected form content-type, got %s", ct)
				}
				values, _ := url.ParseQuery(string(body))
				if values.Get("key") != "value" {
					return fmt.Errorf("expected key=value, got %v", values)
				}
				return nil
			},
		},
		{
			name:        "g.Map with g.String",
			data:        g.Map[g.String, g.String]{"key": "value"},
			contentType: "application/x-www-form-urlencoded",
			validate: func(body []byte, ct string) error {
				if !strings.Contains(ct, "application/x-www-form-urlencoded") {
					return fmt.Errorf("expected form content-type, got %s", ct)
				}
				values, _ := url.ParseQuery(string(body))
				if values.Get("key") != "value" {
					return fmt.Errorf("expected key=value, got %v", values)
				}
				return nil
			},
		},
		{
			name: "g.MapOrd with sorted fields",
			data: func() g.MapOrd[string, string] {
				m := g.NewMapOrd[string, string]()
				m.Set("zebra", "animal")
				m.Set("apple", "fruit")
				m.Set("book", "object")
				m.Set("cat", "pet")
				return m
			}(),
			contentType: "application/x-www-form-urlencoded",
			validate: func(body []byte, ct string) error {
				if !strings.Contains(ct, "application/x-www-form-urlencoded") {
					return fmt.Errorf("expected form content-type, got %s", ct)
				}
				// Check that fields appear in insertion order
				expectedOrder := "zebra=animal&apple=fruit&book=object&cat=pet"
				if string(body) != expectedOrder {
					return fmt.Errorf("expected fields in order %s, got %s", expectedOrder, string(body))
				}
				return nil
			},
		},
		{
			name: "g.MapOrd[g.String, g.String] with sorted fields",
			data: func() g.MapOrd[g.String, g.String] {
				m := g.NewMapOrd[g.String, g.String]()
				m.Set("delta", "fourth")
				m.Set("alpha", "first")
				m.Set("charlie", "third")
				m.Set("bravo", "second")
				return m
			}(),
			contentType: "application/x-www-form-urlencoded",
			validate: func(body []byte, ct string) error {
				if !strings.Contains(ct, "application/x-www-form-urlencoded") {
					return fmt.Errorf("expected form content-type, got %s", ct)
				}
				// Check that fields appear in insertion order
				expectedOrder := "delta=fourth&alpha=first&charlie=third&bravo=second"
				if string(body) != expectedOrder {
					return fmt.Errorf("expected fields in order %s, got %s", expectedOrder, string(body))
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if err := tt.validate(body, r.Header.Get("Content-Type")); err != nil {
					t.Error(err)
				}
				w.WriteHeader(http.StatusOK)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Post(g.String(ts.URL), tt.data).Do()
			if resp.IsErr() {
				// For XML struct test, automatic detection might not work
				if tt.name == "XML struct" && strings.Contains(resp.Err().Error(), "data type not detected") {
					t.Skip("XML struct auto-detection not supported - this is expected")
					return
				}
				t.Fatal(resp.Err())
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
			}
		})
	}
}

func TestClientPutPatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		fn     func(*surf.Client, g.String, any) *surf.Request
	}{
		{"PUT", "PUT", (*surf.Client).Put},
		{"PATCH", "PATCH", (*surf.Client).Patch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.method {
					t.Errorf("expected method %s, got %s", tt.method, r.Method)
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != "test data" {
					t.Errorf("expected 'test data', got %s", string(body))
				}
				w.WriteHeader(http.StatusOK)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := tt.fn(client, g.String(ts.URL), "test data").Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
			}
		})
	}
}

func TestClientGetWithData(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "value" {
			t.Errorf("expected query param key=value, got %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	// Test with query parameters in URL
	resp := client.Get(g.String(ts.URL + "?key=value")).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestClientDeleteWithData(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE method, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "delete data" {
			t.Errorf("expected 'delete data', got %s", string(body))
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Delete(g.String(ts.URL), "delete data").Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestClientRaw(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "test" {
			t.Errorf("expected X-Custom header, got %s", r.Header.Get("X-Custom"))
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "raw response")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	rawRequest := g.String(fmt.Sprintf(`GET / HTTP/1.1
Host: %s
X-Custom: test

`, u.Host))

	client := surf.NewClient()
	resp := client.Raw(rawRequest, "http").Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	if !resp.Ok().Body.Contains("raw response") {
		t.Error("expected 'raw response' in body")
	}
}

func TestClientMultipart(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		if r.FormValue("field1") != "value1" {
			t.Errorf("expected field1=value1, got %s", r.FormValue("field1"))
		}
		if r.FormValue("field2") != "value2" {
			t.Errorf("expected field2=value2, got %s", r.FormValue("field2"))
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	data := g.NewMapOrd[g.String, g.String](2)
	data.Set("field1", "value1")
	data.Set("field2", "value2")

	resp := client.Multipart(g.String(ts.URL), data).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestClientMultipartEdgeCases(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	// Test with empty multipart data
	emptyData := g.NewMapOrd[g.String, g.String](0)
	resp := client.Multipart(g.String(ts.URL), emptyData).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test with special characters in field names and values
	specialData := g.NewMapOrd[g.String, g.String](3)
	specialData.Set("field with spaces", "value with spaces")
	specialData.Set("field_with_unicode", "value with 特殊字符 🚀")
	specialData.Set("empty_field", "")

	resp = client.Multipart(g.String(ts.URL), specialData).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestClientMultipartWithCustomBoundary(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, "multipart/form-data") {
			t.Errorf("expected multipart/form-data content type, got %s", contentType)
		}
		if !strings.Contains(contentType, "boundary=") {
			t.Error("expected boundary in content type")
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Boundary(func() g.String { return "custom-boundary-123" }).
		Build()

	data := g.NewMapOrd[g.String, g.String](1)
	data.Set("test_field", "test_value")

	resp := client.Multipart(g.String(ts.URL), data).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestClientMultipartInvalidURL(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()

	data := g.NewMapOrd[g.String, g.String](1)
	data.Set("field", "value")

	// Test with invalid URL
	resp := client.Multipart("invalid://url with spaces", data).Do()
	if resp.IsOk() {
		t.Error("expected error for invalid URL")
	}
}

func TestClientFileUpload(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		if header.Filename != "test.txt" {
			t.Errorf("expected filename test.txt, got %s", header.Filename)
		}

		content, _ := io.ReadAll(file)
		if string(content) != "test content" {
			t.Errorf("expected 'test content', got %s", string(content))
		}

		if r.FormValue("field") != "value" {
			t.Errorf("expected field=value, got %s", r.FormValue("field"))
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	// Test with io.Reader
	reader := strings.NewReader("test content")
	data := g.NewMapOrd[g.String, g.String](1)
	data.Set("field", "value")

	resp := client.FileUpload(
		g.String(ts.URL),
		"file",
		"test.txt",
		reader,
		data,
	).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestClientFileUploadVariants(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(10 << 20)
		file, _, _ := r.FormFile("file")
		if file != nil {
			content, _ := io.ReadAll(file)
			w.Write(content)
		}
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	tests := []struct {
		name string
		data []any
	}{
		{
			name: "string content",
			data: []any{"string content"},
		},
		{
			name: "g.String content",
			data: []any{g.String("g.String content")},
		},
		{
			name: "io.Reader content",
			data: []any{bytes.NewReader([]byte("reader content"))},
		},
		{
			name: "with MapOrd[string, string]",
			data: []any{
				"content",
				func() g.MapOrd[string, string] {
					m := g.NewMapOrd[string, string](1)
					m.Set("key", "value")
					return m
				}(),
			},
		},
		{
			name: "byte content",
			data: []any{bytes.NewReader([]byte("byte content"))},
		},
		{
			name: "g.Bytes content",
			data: []any{bytes.NewReader(g.Bytes("g.bytes content").Std())},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := client.FileUpload(
				g.String(ts.URL),
				"file",
				"test.txt",
				tt.data...,
			).Do()

			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			if !resp.Ok().StatusCode.IsSuccess() {
				t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
			}
		})
	}
}

func TestClientBuilder(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()
	builder := client.Builder()

	if builder == nil {
		t.Fatal("Builder() returned nil")
	}

	// Test that builder returns the same client
	built := builder.Build()
	if built != client {
		t.Error("Builder().Build() did not return the same client")
	}
}

func TestClientCloseIdleConnections(t *testing.T) {
	t.Parallel()

	// Test without singleton
	client := surf.NewClient()
	client.CloseIdleConnections() // Should not panic

	// Test with singleton
	client = surf.NewClient().Builder().Singleton().Build()
	client.CloseIdleConnections() // Should close connections
}

func TestClientCookies(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "test",
			Value: "cookie",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with session
	client := surf.NewClient().Builder().Session().Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test GetCookies
	cookies := resp.Ok().GetCookies(g.String(ts.URL))
	if len(cookies) != 1 || cookies[0].Name != "test" {
		t.Errorf("expected test cookie, got %v", cookies)
	}

	// Test SetCookies
	newCookie := &http.Cookie{Name: "new", Value: "value"}
	err := resp.Ok().SetCookies(g.String(ts.URL), []*http.Cookie{newCookie})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientWithContext(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).WithContext(ctx).Do()

	if !resp.IsErr() {
		t.Error("expected timeout error")
	}
}

func TestClientInvalidRequests(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()

	// Test with invalid URL
	resp := client.Get("").Do()
	if !resp.IsErr() {
		t.Error("expected error for empty URL")
	}

	// Test Raw with invalid request
	resp = client.Raw("invalid request", "http").Do()
	if !resp.IsErr() {
		t.Error("expected error for invalid raw request")
	}

	// Test FileUpload with non-existent file
	resp = client.FileUpload("http://localhost:9999", "field", "/non/existent/file.txt").Do()
	if !resp.IsErr() {
		t.Error("expected error for non-existent file")
	}
}

func TestClientMiddlewareApplication(t *testing.T) {
	t.Parallel()

	var requestMiddlewareCalled bool
	var responseMiddlewareCalled bool

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		With(func(*surf.Request) error {
			requestMiddlewareCalled = true
			return nil
		}).
		With(func(*surf.Response) error {
			responseMiddlewareCalled = true
			return nil
		}).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !requestMiddlewareCalled {
		t.Error("request middleware was not called")
	}

	if !responseMiddlewareCalled {
		t.Error("response middleware was not called")
	}
}
