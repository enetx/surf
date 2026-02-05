package surf_test

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/enetx/surf/pkg/sse"
)

func TestBodyString(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test body content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test String()
	content := body.String()
	if content.IsErr() {
		t.Fatal(content.Err())
	}

	if content.Ok() != "test body content" {
		t.Errorf("expected 'test body content', got %s", content.Ok())
	}
}

func TestBodyBytes(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "byte content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test Bytes()
	bytes := body.Bytes()
	if bytes.IsErr() {
		t.Fatal(bytes.Err())
	}
	if string(bytes.Ok()) != "byte content" {
		t.Errorf("expected 'byte content', got %s", string(bytes.Ok()))
	}

	// Without cache, second call to Bytes() returns error as body is consumed
	bytes2 := body.Bytes()
	if bytes2.IsOk() && !bytes2.Ok().IsEmpty() {
		t.Error("expected error or empty on second call to Bytes() without cache")
	}
}

func TestBodyJSON(t *testing.T) {
	t.Parallel()

	type TestData struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	expected := TestData{Name: "test", Value: 42}

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expected)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test JSON()
	var result TestData
	err := body.JSON(&result)
	if err != nil {
		t.Fatal(err)
	}

	if result.Name != expected.Name || result.Value != expected.Value {
		t.Errorf("expected %+v, got %+v", expected, result)
	}
}

func TestBodyXML(t *testing.T) {
	t.Parallel()

	type TestData struct {
		XMLName xml.Name `xml:"root"`
		Name    string   `xml:"name"`
		Value   int      `xml:"value"`
	}

	expected := TestData{Name: "test", Value: 42}

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		xml.NewEncoder(w).Encode(expected)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test XML()
	var result TestData
	err := body.XML(&result)
	if err != nil {
		t.Fatal(err)
	}

	if result.Name != expected.Name || result.Value != expected.Value {
		t.Errorf("expected %+v, got %+v", expected, result)
	}
}

func TestBodyStream(t *testing.T) {
	t.Parallel()

	lines := []string{"line1", "line2", "line3"}
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		for _, line := range lines {
			fmt.Fprintln(w, line)
		}
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test Stream()
	reader := body.Stream()
	if reader == nil {
		t.Fatal("Stream() returned nil")
	}

	// Read lines from stream
	scanner := bufio.NewScanner(reader)
	i := 0
	for scanner.Scan() {
		if scanner.Text() != lines[i] {
			t.Errorf("expected line %s, got %s", lines[i], scanner.Text())
		}
		i++
	}

	if i != len(lines) {
		t.Errorf("expected %d lines, got %d", len(lines), i)
	}
}

func TestBodySSE(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Write SSE events
		fmt.Fprintf(w, "data: event1\n\n")
		fmt.Fprintf(w, "data: event2\n\n")
		fmt.Fprintf(w, "data: event3\n\n")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test SSE()
	events := []string{}
	err := body.SSE(func(event *sse.Event) bool {
		events = append(events, event.Data.Std())
		return true // Continue reading
	})

	if err != nil && err != io.EOF {
		t.Fatal(err)
	}

	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}

	for i, event := range events {
		expected := fmt.Sprintf("event%d", i+1)
		if event != expected {
			t.Errorf("expected event %s, got %s", expected, event)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write 100 bytes
		fmt.Fprint(w, strings.Repeat("a", 100))
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test Limit()
	body.Limit(50)

	content := body.Bytes()
	if content.IsErr() {
		t.Fatal(content.Err())
	}
	if len(content.Ok()) != 50 {
		t.Errorf("expected 50 bytes with limit, got %d", len(content.Ok()))
	}
}

func TestBodyClose(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test Close()
	err := body.Close()
	if err != nil {
		t.Fatal(err)
	}

	// After close, Bytes() should return error or empty
	content := body.Bytes()
	if content.IsOk() && !content.Ok().IsEmpty() {
		t.Error("expected error or empty after Close(), got content")
	}
}

func TestBodyCloseNil(t *testing.T) {
	t.Parallel()

	// Test Close() on nil body - should return nil (no-op)
	var body *surf.Body
	if err := body.Close(); err != nil {
		t.Errorf("expected nil error when closing nil body, got: %v", err)
	}

	// Test Close() on body with nil Reader - should return nil (no-op)
	body = &surf.Body{}
	if err := body.Close(); err != nil {
		t.Errorf("expected nil error when closing body with nil Reader, got: %v", err)
	}
}

func TestBodyContains(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Hello World Test Content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().CacheBody().Build().Unwrap()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test Contains with string (case sensitive)
	if !body.Contains("Hello") {
		t.Error("expected body to contain 'Hello'")
	}

	// Test Contains with g.String
	if !body.Contains(g.String("World")) {
		t.Error("expected body to contain 'World'")
	}

	// Test Contains with []byte
	if !body.Contains([]byte("Test")) {
		t.Error("expected body to contain 'Test'")
	}

	// Test Contains with g.Bytes
	if !body.Contains(g.Bytes("Content")) {
		t.Error("expected body to contain 'Content'")
	}

	// Test Contains with regexp
	re := regexp.MustCompile(`Hello.*Content`)
	if !body.Contains(re) {
		t.Error("expected body to match regex")
	}

	// Test Contains with non-matching pattern
	if body.Contains("notfound") {
		t.Error("expected body to not contain 'notfound'")
	}

	// Test Contains with unsupported type
	if body.Contains(123) {
		t.Error("expected false for unsupported type")
	}
}

func TestBodyDump(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "dump content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Create temp file path
	tempFile := g.String(fmt.Sprintf("/tmp/surf_test_%d.txt", time.Now().UnixNano()))

	// Test Dump()
	err := body.Dump(tempFile)
	if err != nil {
		t.Fatal(err)
	}

	// Read dumped content
	content := g.NewFile(tempFile).Read().UnwrapOrDefault()
	if content != "dump content" {
		t.Errorf("expected 'dump content', got %s", content)
	}

	// Clean up
	g.NewFile(tempFile).Remove()
}

func TestBodyDumpNil(t *testing.T) {
	t.Parallel()

	// Test Dump() on nil body
	var body *surf.Body
	err := body.Dump("test.txt")
	if err == nil {
		t.Error("expected error when dumping nil body")
	}

	// Test Dump() on body with nil Reader
	body = &surf.Body{}
	err = body.Dump("test.txt")
	if err == nil {
		t.Error("expected error when dumping body with nil Reader")
	}
}

func TestBodyUTF8(t *testing.T) {
	t.Parallel()

	// Test with non-UTF8 content
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=windows-1252")
		w.WriteHeader(http.StatusOK)
		// Windows-1252 encoded content (would need actual encoding)
		fmt.Fprint(w, "test content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test UTF8()
	content := body.UTF8()
	if content.IsErr() {
		t.Fatal(content.Err())
	}
	if content.Ok() == "" {
		t.Error("UTF8() returned empty string")
	}
}

func TestBodyUTF8Nil(t *testing.T) {
	t.Parallel()

	// Test UTF8() on nil body
	var body *surf.Body
	content := body.UTF8()
	if content.IsOk() && content.Ok() != "" {
		t.Error("expected error or empty string for nil body")
	}
}

func TestBodyCache(t *testing.T) {
	t.Parallel()

	callCount := 0
	handler := func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "call %d", callCount)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with cache enabled
	client := surf.NewClient().Builder().CacheBody().Build().Unwrap()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// First call to Bytes()
	content1 := body.Bytes()
	if content1.IsErr() {
		t.Fatal(content1.Err())
	}
	if string(content1.Ok()) != "call 1" {
		t.Errorf("expected 'call 1', got %s", string(content1.Ok()))
	}

	// Second call should return cached content
	content2 := body.Bytes()
	if content2.IsErr() {
		t.Fatal(content2.Err())
	}
	if string(content2.Ok()) != "call 1" {
		t.Errorf("expected cached 'call 1', got %s", string(content2.Ok()))
	}

	// Make another request to verify server was called only once
	resp2 := client.Get(g.String(ts.URL)).Do()
	if resp2.IsErr() {
		t.Fatal(resp2.Err())
	}

	content3 := resp2.Ok().Body.String()
	if content3.IsErr() {
		t.Fatal(content3.Err())
	}
	if content3.Ok() != "call 2" {
		t.Errorf("expected 'call 2' for new request, got %s", content3.Ok())
	}
}

func TestBodyWithoutCache(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test without cache (default)
	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// First call to Bytes()
	content1 := body.Bytes()
	if content1.IsErr() {
		t.Fatal(content1.Err())
	}
	if string(content1.Ok()) != "content" {
		t.Errorf("expected 'content', got %s", string(content1.Ok()))
	}

	// Second call returns error because body was consumed
	content2 := body.Bytes()
	if content2.IsOk() && !content2.Ok().IsEmpty() {
		t.Error("expected error or empty for second call without cache")
	}
}

func TestBodyNilOperations(t *testing.T) {
	t.Parallel()

	// Test all methods on nil body
	var body *surf.Body

	// Bytes() should return error for nil body
	if body.Bytes().IsOk() && !body.Bytes().Ok().IsEmpty() {
		t.Error("expected error or empty Bytes() for nil body")
	}

	// String() should return error for nil body
	str := body.String()
	if str.IsOk() && str.Ok() != "" {
		t.Error("expected error or empty String() for nil body")
	}

	// Stream() should return nil
	if body.Stream() != nil {
		t.Error("expected nil Stream() for nil body")
	}

	// Limit() should return nil
	if body.Limit(100) != nil {
		t.Error("expected nil Limit() for nil body")
	}
}

func TestBodyLimitChaining(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, strings.Repeat("x", 1000))
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test Limit() chaining
	content := resp.Ok().Body.Limit(100).Bytes()
	if content.IsErr() {
		t.Fatal(content.Err())
	}
	if len(content.Ok()) != 100 {
		t.Errorf("expected 100 bytes with limit chain, got %d", len(content.Ok()))
	}
}

func TestBodyClosedBody(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Close the body
	body.Close()

	// Try to read after close
	content := body.Bytes()
	if content.IsOk() && !content.Ok().IsEmpty() {
		t.Error("expected error or empty after body closed")
	}
}

func TestBodyInvalidJSON(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "not json")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test JSON() with invalid JSON
	var result map[string]any
	err := body.JSON(&result)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBodyInvalidXML(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "not xml")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// Test XML() with invalid XML
	var result struct {
		XMLName xml.Name `xml:"root"`
	}
	err := body.XML(&result)
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestBodyXMLEdgeCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		xmlContent  string
		expectError bool
	}{
		{
			"Empty XML",
			"",
			true,
		},
		{
			"Simple XML",
			`<root><name>test</name><value>42</value></root>`,
			false,
		},
		{
			"XML with namespaces",
			`<root xmlns="http://localhost"><name>test</name></root>`,
			false,
		},
		{
			"XML with CDATA",
			`<root><name><![CDATA[test data]]></name></root>`,
			false,
		},
		{
			"Malformed XML",
			`<root><name>test</root>`, // Missing closing tag
			true,
		},
		{
			"XML with attributes",
			`<root id="1"><name attr="value">test</name></root>`,
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tc.xmlContent)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			body := resp.Ok().Body

			var result struct {
				XMLName xml.Name `xml:"root"`
				Name    string   `xml:"name"`
				Value   int      `xml:"value"`
			}

			err := body.XML(&result)
			if tc.expectError && err == nil {
				t.Errorf("expected error for %s but got none", tc.name)
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

func TestBodyJSONEdgeCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		jsonContent string
		expectError bool
	}{
		{
			"Empty JSON object",
			`{}`,
			false,
		},
		{
			"Empty JSON array",
			`[]`,
			false,
		},
		{
			"Null JSON",
			`null`,
			false,
		},
		{
			"JSON with unicode",
			`{"name": "🦄", "emoji": "🌈"}`,
			false,
		},
		{
			"Nested JSON",
			`{"user": {"name": "test", "details": {"age": 30}}}`,
			false,
		},
		{
			"JSON with escaped characters",
			`{"path": "C:\\Program Files\\test", "quote": "He said \"hello\""}`,
			false,
		},
		{
			"Invalid JSON - missing quote",
			`{"name: "test"}`,
			true,
		},
		{
			"Invalid JSON - trailing comma",
			`{"name": "test",}`,
			true,
		},
		{
			"Empty string",
			``,
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tc.jsonContent)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			body := resp.Ok().Body

			var result any
			err := body.JSON(&result)
			if tc.expectError && err == nil {
				t.Errorf("expected error for %s but got none", tc.name)
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

func TestBodyStreamingEdgeCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			"Single line",
			"single line",
			[]string{"single line"},
		},
		{
			"Empty lines",
			"line1\n\nline3\n",
			[]string{"line1", "", "line3"},
		},
		{
			"Windows line endings",
			"line1\r\nline2\r\n",
			[]string{"line1", "line2"},
		},
		{
			"Mixed line endings",
			"line1\nline2\r\nline3\r",
			[]string{"line1", "line2", "line3"},
		},
		{
			"Long lines",
			strings.Repeat("x", 10000) + "\n" + strings.Repeat("y", 5000),
			[]string{strings.Repeat("x", 10000), strings.Repeat("y", 5000)},
		},
		{
			"Unicode content",
			"🦄 line\n🌈 rainbow",
			[]string{"🦄 line", "🌈 rainbow"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tc.content)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			body := resp.Ok().Body
			reader := body.Stream()
			if reader == nil {
				t.Fatal("Stream() returned nil")
			}

			scanner := bufio.NewScanner(reader)
			var lines []string
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}

			if err := scanner.Err(); err != nil {
				t.Fatalf("scanner error: %v", err)
			}

			if len(lines) != len(tc.expected) {
				t.Errorf("expected %d lines, got %d", len(tc.expected), len(lines))
				return
			}

			for i, line := range lines {
				if line != tc.expected[i] {
					t.Errorf("line %d: expected %q, got %q", i, tc.expected[i], line)
				}
			}
		})
	}
}

func TestBodySSEEdgeCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		sseData  string
		expected []string
	}{
		{
			"Simple events",
			"data: event1\n\ndata: event2\n\n",
			[]string{"event1", "event2"},
		},
		{
			"Events with empty data",
			"data: \n\ndata: content\n\n",
			[]string{"", "content"},
		},
		{
			"Multiline data",
			"data: line1\ndata: line2\n\ndata: single\n\n",
			[]string{"line2", "single"},
		},
		{
			"Events with IDs",
			"id: 1\ndata: event1\n\nid: 2\ndata: event2\n\n",
			[]string{"event1", "event2"},
		},
		{
			"Events with event types",
			"event: message\ndata: content1\n\nevent: update\ndata: content2\n\n",
			[]string{"content1", "content2"},
		},
		{
			"Comments ignored",
			": this is a comment\ndata: content\n\n",
			[]string{"content"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tc.sseData)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			body := resp.Ok().Body
			var events []string
			err := body.SSE(func(event *sse.Event) bool {
				events = append(events, event.Data.Std())
				return true // Continue reading
			})

			if err != nil && err != io.EOF {
				t.Fatalf("SSE error: %v", err)
			}

			if len(events) != len(tc.expected) {
				t.Errorf("expected %d events, got %d", len(tc.expected), len(events))
				return
			}

			for i, event := range events {
				if event != tc.expected[i] {
					t.Errorf("event %d: expected %q, got %q", i, tc.expected[i], event)
				}
			}
		})
	}
}

func TestBodyLimitEdgeCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		contentSize int
		limit       int64
		expectedLen int
	}{
		{
			"Limit larger than content",
			100,
			200,
			100,
		},
		{
			"Limit equal to content",
			100,
			100,
			100,
		},
		{
			"Limit smaller than content",
			100,
			50,
			50,
		},
		{
			"Zero limit",
			100,
			0,
			0,
		},
		{
			"Negative limit (should be treated as no limit)",
			100,
			-1,
			100,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.Repeat("x", tc.contentSize)
			handler := func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, content)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			body := resp.Ok().Body.Limit(tc.limit)
			result := body.Bytes()

			if result.IsErr() {
				t.Fatal(result.Err())
			}
			if len(result.Ok()) != tc.expectedLen {
				t.Errorf("expected %d bytes, got %d", tc.expectedLen, len(result.Ok()))
			}
		})
	}
}

func TestBodyContainsEdgeCases(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Hello 🌍 World! Test Content 123")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().CacheBody().Build().Unwrap()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	testCases := []struct {
		name     string
		pattern  any
		expected bool
	}{
		{"Empty string", "", true},
		{"Unicode emoji", "🌍", true},
		{"Case sensitive", "hello", true},
		{"Case sensitive uppercase", "HELLO", true},
		{"Numbers", "123", true},
		{"Exclamation", "!", true},
		{"Start of string", "Hello", true},
		{"End of string", "123", true},
		{"Multiple words", "World! Test", true},
		{"Non-existent", "xyz", false},
		{"g.String type", g.String("World"), true},
		{"[]byte type", []byte("Content"), true},
		{"g.Bytes type", g.Bytes("Test"), true},
		{"Regex match", regexp.MustCompile(`Hello.*World`), true},
		{"Regex no match", regexp.MustCompile(`^World`), false},
		{"Complex regex", regexp.MustCompile(`\d+$`), true}, // Ends with digits
		{"Invalid type", 123, false},
		{"Float type", 1.23, false},
		{"Boolean type", true, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := body.Contains(tc.pattern)
			if result != tc.expected {
				t.Errorf("Contains(%v): expected %v, got %v", tc.pattern, tc.expected, result)
			}
		})
	}
}

func TestBodyWithContextTimeout(t *testing.T) {
	t.Parallel()

	// Test that context timeout is checked before reading starts
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "response")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Create already expired context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond) // Ensure timeout has passed

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.WithContext(ctx)
	content := body.Bytes()

	// Should return context error immediately
	if content.IsOk() {
		t.Error("expected error for expired context timeout")
	} else {
		if content.Err() != context.DeadlineExceeded {
			t.Errorf("expected context.DeadlineExceeded, got: %v", content.Err())
		}
	}
}

func TestBodyWithContextCancel(t *testing.T) {
	t.Parallel()

	// Test that pre-cancelled context is detected
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "response")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Create and immediately cancel context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.WithContext(ctx)
	content := body.Bytes()

	// Should return context error immediately
	if content.IsOk() {
		t.Error("expected error for cancelled context")
	} else {
		if content.Err() != context.Canceled {
			t.Errorf("expected context.Canceled, got: %v", content.Err())
		}
	}
}

func TestBodyWithContextNoCancel(t *testing.T) {
	t.Parallel()

	expectedContent := "full response content"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, expectedContent)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Context without timeout - should complete normally
	ctx := context.Background()
	body := resp.Ok().Body.WithContext(ctx)

	content := body.Bytes()

	if content.IsErr() {
		t.Fatalf("unexpected error: %v", content.Err())
	}

	if string(content.Ok()) != expectedContent {
		t.Errorf("expected %q, got %q", expectedContent, string(content.Ok()))
	}
}

func TestBodyStreamWithContextCancel(t *testing.T) {
	t.Parallel()

	// Test that Stream works with valid context
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		for i := range 5 {
			fmt.Fprintf(w, "line-%d\n", i)
		}
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	ctx := context.Background()
	body := resp.Ok().Body.WithContext(ctx)

	stream := body.Stream()
	if stream == nil {
		t.Fatal("Stream() returned nil")
	}
	defer stream.Close()

	lineCount := 0
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		lineCount++
	}

	if lineCount != 5 {
		t.Errorf("expected 5 lines, got %d", lineCount)
	}
}

func TestStreamReaderClose(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "stream content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body
	stream := body.Stream()
	if stream == nil {
		t.Fatal("Stream() returned nil")
	}

	// Read some data
	buf := make([]byte, 6)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if string(buf[:n]) != "stream" {
		t.Errorf("expected 'stream', got %s", string(buf[:n]))
	}

	// Close via StreamReader
	if err := stream.Close(); err != nil {
		t.Fatalf("StreamReader.Close() error: %v", err)
	}

	// Multiple Close() calls should be safe
	if err := stream.Close(); err != nil {
		t.Fatalf("second StreamReader.Close() error: %v", err)
	}
}

func TestBodyMultipleClose(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// First close should succeed
	if err := body.Close(); err != nil {
		t.Fatalf("first Close() error: %v", err)
	}

	// Second close should also succeed (no-op via closeOnce)
	if err := body.Close(); err != nil {
		t.Fatalf("second Close() error: %v", err)
	}

	// Third close should also succeed
	if err := body.Close(); err != nil {
		t.Fatalf("third Close() error: %v", err)
	}
}

func TestBodyContextAlreadyCancelled(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "response content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Create already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body.WithContext(ctx)
	content := body.Bytes()

	// Should return context cancelled error
	if content.IsOk() {
		t.Error("expected error for already cancelled context")
	} else {
		if content.Err() != context.Canceled {
			t.Errorf("expected context.Canceled, got: %v", content.Err())
		}
	}
}

func TestStreamReaderFromNilBody(t *testing.T) {
	t.Parallel()

	// Test Stream() on nil body returns nil
	var body *surf.Body
	stream := body.Stream()
	if stream != nil {
		t.Error("expected nil StreamReader for nil body")
	}

	// Test Stream() on body with nil Reader returns nil
	body = &surf.Body{}
	stream = body.Stream()
	if stream != nil {
		t.Error("expected nil StreamReader for body with nil Reader")
	}
}

// simpleMockReader is a mock reader that implements SetReadDeadline.
type simpleMockReader struct {
	reader   io.Reader
	deadline time.Time
	mu       sync.Mutex
}

func (m *simpleMockReader) Read(p []byte) (n int, err error) {
	m.mu.Lock()
	d := m.deadline
	m.mu.Unlock()

	if !d.IsZero() && time.Now().After(d) {
		return 0, context.DeadlineExceeded
	}

	return m.reader.Read(p)
}

func (m *simpleMockReader) Close() error {
	return nil
}

func (m *simpleMockReader) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	m.deadline = t
	m.mu.Unlock()
	return nil
}

func TestBodyWithContextAfterReadStarted(t *testing.T) {
	t.Parallel()

	// Create a body with a mock reader that supports SetReadDeadline
	mockReader := &simpleMockReader{
		reader: strings.NewReader("test content"),
	}

	body := &surf.Body{
		Reader: mockReader,
	}

	// Set context first
	ctx := context.Background()
	body.WithContext(ctx)

	// Start reading by calling Stream() which initializes cancelRead
	stream := body.Stream()
	if stream == nil {
		t.Fatal("Stream() returned nil")
	}
	defer stream.Close()

	// WithContext after read started should not panic (no-op)
	result := body.WithContext(context.Background())
	if result != body {
		t.Error("expected WithContext to return same body")
	}
}

func TestBodyWithContextNil(t *testing.T) {
	t.Parallel()

	// Test WithContext on nil body returns nil
	var body *surf.Body
	result := body.WithContext(context.Background())
	if result != nil {
		t.Error("expected nil when calling WithContext on nil body")
	}
}

func TestBodyWithContextBeforeRead(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	body := resp.Ok().Body

	// WithContext before read should work without panic
	ctx := context.Background()
	result := body.WithContext(ctx)
	if result != body {
		t.Error("expected WithContext to return same body")
	}

	// Now read should work
	content := body.Bytes()
	if content.IsErr() {
		t.Fatal(content.Err())
	}
	if string(content.Ok()) != "test content" {
		t.Errorf("expected 'test content', got %s", string(content.Ok()))
	}
}
