package surf_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func TestMultipartFields(t *testing.T) {
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

	mp := surf.NewMultipart().
		Field("field1", "value1").
		Field("field2", "value2")

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartFileString(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		file, header, err := r.FormFile("document")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		if header.Filename != "test.txt" {
			t.Errorf("expected filename test.txt, got %s", header.Filename)
		}

		content, _ := io.ReadAll(file)
		if string(content) != "hello world" {
			t.Errorf("expected 'hello world', got %s", string(content))
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	mp := surf.NewMultipart().
		FileString("document", "test.txt", "hello world")

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartFileBytes(t *testing.T) {
	t.Parallel()

	testData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		file, header, err := r.FormFile("binary")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		if header.Filename != "data.bin" {
			t.Errorf("expected filename data.bin, got %s", header.Filename)
		}

		content, _ := io.ReadAll(file)
		if !bytes.Equal(content, testData) {
			t.Errorf("expected %v, got %v", testData, content)
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	mp := surf.NewMultipart().
		FileBytes("binary", "data.bin", testData)

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartFileReader(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		file, header, err := r.FormFile("upload")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		if header.Filename != "stream.txt" {
			t.Errorf("expected filename stream.txt, got %s", header.Filename)
		}

		content, _ := io.ReadAll(file)
		if string(content) != "streamed content" {
			t.Errorf("expected 'streamed content', got %s", string(content))
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	mp := surf.NewMultipart().
		FileReader("upload", "stream.txt", strings.NewReader("streamed content"))

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartCustomContentType(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		file, header, err := r.FormFile("config")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		ct := header.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	mp := surf.NewMultipart().
		FileString("config", "config.txt", `{"key": "value"}`).
		ContentType("application/json")

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartCustomFileName(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		file, header, err := r.FormFile("doc")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		if header.Filename != "renamed.pdf" {
			t.Errorf("expected filename renamed.pdf, got %s", header.Filename)
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	mp := surf.NewMultipart().
		FileString("doc", "original.txt", "content").
		FileName("renamed.pdf")

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartMixed(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		// Check fields
		if r.FormValue("user_id") != "123" {
			t.Errorf("expected user_id=123, got %s", r.FormValue("user_id"))
		}
		if r.FormValue("action") != "upload" {
			t.Errorf("expected action=upload, got %s", r.FormValue("action"))
		}

		// Check first file
		file1, header1, err := r.FormFile("doc1")
		if err != nil {
			t.Fatal(err)
		}
		defer file1.Close()

		if header1.Filename != "document.txt" {
			t.Errorf("expected filename document.txt, got %s", header1.Filename)
		}

		content1, _ := io.ReadAll(file1)
		if string(content1) != "doc content" {
			t.Errorf("expected 'doc content', got %s", string(content1))
		}

		// Check second file
		file2, header2, err := r.FormFile("doc2")
		if err != nil {
			t.Fatal(err)
		}
		defer file2.Close()

		if header2.Filename != "data.json" {
			t.Errorf("expected filename data.json, got %s", header2.Filename)
		}

		ct := header2.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	mp := surf.NewMultipart().
		Field("user_id", "123").
		Field("action", "upload").
		FileString("doc1", "document.txt", "doc content").
		FileString("doc2", "data.json", `{"key": "value"}`).ContentType("application/json")

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartWithCustomBoundary(t *testing.T) {
	t.Parallel()

	expectedBoundary := "custom-boundary-12345"

	handler := func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, "multipart/form-data") {
			t.Errorf("expected multipart/form-data content type, got %s", contentType)
		}
		if !strings.Contains(contentType, "boundary="+expectedBoundary) {
			t.Errorf("expected boundary=%s in content type, got %s", expectedBoundary, contentType)
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Boundary(func() g.String { return g.String(expectedBoundary) }).
		Build().Unwrap()

	mp := surf.NewMultipart().
		Field("test", "value")

	resp := client.Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartEmptyFields(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	mp := surf.NewMultipart()

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartSpecialCharacters(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		if r.FormValue("field with spaces") != "value with spaces" {
			t.Errorf("unexpected value for 'field with spaces'")
		}
		if r.FormValue("unicode_field") != "特殊字符 🚀" {
			t.Errorf("unexpected value for unicode_field")
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	mp := surf.NewMultipart().
		Field("field with spaces", "value with spaces").
		Field("unicode_field", "特殊字符 🚀")

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartNil(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(nil).Do()
	if resp.IsOk() {
		t.Error("expected error for nil multipart")
	}
}

func TestMultipartContentTypeAutoDetection(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		// Check .json file gets application/json
		file1, header1, _ := r.FormFile("config")
		if file1 != nil {
			defer file1.Close()
			ct := header1.Header.Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("expected application/json for .json file, got %s", ct)
			}
		}

		// Check .txt file gets text/plain
		file2, header2, _ := r.FormFile("readme")
		if file2 != nil {
			defer file2.Close()
			ct := header2.Header.Get("Content-Type")
			if !strings.HasPrefix(ct, "text/plain") {
				t.Errorf("expected text/plain for .txt file, got %s", ct)
			}
		}

		// Check unknown extension gets application/octet-stream
		file3, header3, _ := r.FormFile("data")
		if file3 != nil {
			defer file3.Close()
			ct := header3.Header.Get("Content-Type")
			if ct != "application/octet-stream" {
				t.Errorf("expected application/octet-stream for unknown extension, got %s", ct)
			}
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	mp := surf.NewMultipart().
		FileString("config", "config.json", `{}`).
		FileString("readme", "readme.txt", "text").
		FileString("data", "file.unknownext", "data")

	resp := surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartRetry(t *testing.T) {
	t.Parallel()

	var attempts int
	expectedData := "retry test data"

	handler := func(w http.ResponseWriter, r *http.Request) {
		attempts++

		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatalf("attempt %d: failed to parse multipart: %v", attempts, err)
		}

		// Verify field is present on every attempt
		if r.FormValue("field") != expectedData {
			t.Errorf("attempt %d: expected field=%s, got %s", attempts, expectedData, r.FormValue("field"))
		}

		// First attempt returns 500 to trigger retry
		if attempts == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Retry(2, 10*time.Millisecond, 500).
		Build().Unwrap()

	mp := surf.NewMultipart().Field("field", g.String(expectedData)).Retry(true)

	resp := client.Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartRetryWithFile(t *testing.T) {
	t.Parallel()

	var attempts int
	expectedContent := "file content for retry"

	handler := func(w http.ResponseWriter, r *http.Request) {
		attempts++

		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatalf("attempt %d: failed to parse multipart: %v", attempts, err)
		}

		// Verify file is present on every attempt
		file, header, err := r.FormFile("upload")
		if err != nil {
			t.Fatalf("attempt %d: failed to get file: %v", attempts, err)
		}
		defer file.Close()

		if header.Filename != "test.txt" {
			t.Errorf("attempt %d: expected filename test.txt, got %s", attempts, header.Filename)
		}

		content, _ := io.ReadAll(file)
		if string(content) != expectedContent {
			t.Errorf("attempt %d: expected content %q, got %q", attempts, expectedContent, string(content))
		}

		// First attempt returns 503 to trigger retry
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Retry(2, 10*time.Millisecond, 503).
		Build().Unwrap()

	mp := surf.NewMultipart().
		FileString("upload", "test.txt", g.String(expectedContent)).Retry(true)

	resp := client.Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestPostBodyRetry(t *testing.T) {
	t.Parallel()

	var attempts int
	expectedBody := "post body for retry test"

	handler := func(w http.ResponseWriter, r *http.Request) {
		attempts++

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("attempt %d: failed to read body: %v", attempts, err)
		}

		if string(body) != expectedBody {
			t.Errorf("attempt %d: expected body %q, got %q", attempts, expectedBody, string(body))
		}

		// First two attempts return 502 to trigger retry
		if attempts <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Retry(3, 10*time.Millisecond, 502).
		Build().Unwrap()

	resp := client.Post(g.String(ts.URL)).Body(expectedBody).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartWithImpersonate(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatal(err)
		}

		if r.FormValue("key") != "value" {
			t.Errorf("expected key=value, got %s", r.FormValue("key"))
		}

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Impersonate().Firefox().Build().Unwrap()

	mp := surf.NewMultipart().Field("key", "value")

	resp := client.Post(g.String(ts.URL)).Multipart(mp).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}
}

func TestMultipartAndBodyMutuallyExclusive(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	mp := surf.NewMultipart().Field("key", "value")

	// Body() then Multipart() - should error
	resp := surf.NewClient().Post(g.String(ts.URL)).Body("test").Multipart(mp).Do()
	if resp.IsOk() {
		t.Error("expected error when using both Body() and Multipart()")
	}

	if !strings.Contains(resp.Err().Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got: %v", resp.Err())
	}

	// Multipart() then Body() - should also error
	resp = surf.NewClient().Post(g.String(ts.URL)).Multipart(mp).Body("test").Do()
	if resp.IsOk() {
		t.Error("expected error when using both Multipart() and Body()")
	}

	if !strings.Contains(resp.Err().Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error, got: %v", resp.Err())
	}
}
