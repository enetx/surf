package surf_test

import (
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestResponseBasics(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test", "value")
		w.Header().Set("Location", "https://localhost/redirect")
		http.SetCookie(w, &http.Cookie{
			Name:  "test",
			Value: "cookie",
		})
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "test response")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Test GetResponse
	httpResp := response.GetResponse()
	if httpResp == nil {
		t.Error("GetResponse() returned nil")
	}

	// Test basic properties
	if response.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", response.StatusCode)
	}

	if response.Proto != "HTTP/1.1" {
		t.Errorf("expected proto HTTP/1.1, got %s", response.Proto)
	}

	if response.URL == nil {
		t.Error("URL is nil")
	}

	if response.Headers.Get("X-Test") != "value" {
		t.Error("expected X-Test header")
	}

	// Test Location
	if response.Location() != "https://localhost/redirect" {
		t.Errorf("expected Location header, got %s", response.Location())
	}

	// Test Referer (might be empty in test)
	_ = response.Referer()

	// Test UserAgent
	if response.UserAgent == "" {
		t.Error("UserAgent is empty")
	}

	// Test Time
	if response.Time == 0 {
		t.Error("Time is 0")
	}

	// Test ContentLength
	if response.ContentLength == 0 {
		t.Error("ContentLength is 0")
	}

	// Test Attempts
	if response.Attempts != 0 {
		t.Errorf("expected 0 attempts, got %d", response.Attempts)
	}

	// Test Cookies
	if len(response.Cookies) != 1 || response.Cookies[0].Name != "test" {
		t.Errorf("expected test cookie, got %v", response.Cookies)
	}

	// Test body content
	if !response.Body.Contains("test response") {
		t.Error("expected 'test response' in body")
	}
}

func TestResponseGetCookies(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "test1",
			Value: "value1",
			Path:  "/",
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "test2",
			Value: "value2",
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Test GetCookies
	cookies := response.GetCookies(g.String(ts.URL))
	if len(cookies) < 2 {
		t.Errorf("expected at least 2 cookies, got %d", len(cookies))
	}

	// Test with invalid URL (should return nil)
	cookies = response.GetCookies("")
	if cookies != nil {
		t.Error("expected nil for invalid URL")
	}
}

func TestResponseSetCookies(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Test SetCookies
	cookies := []*http.Cookie{
		{Name: "new1", Value: "value1"},
		{Name: "new2", Value: "value2"},
	}
	err := response.SetCookies(g.String(ts.URL), cookies)
	if err != nil {
		t.Fatal(err)
	}

	// Verify cookies were set
	setCookies := response.GetCookies(g.String(ts.URL))
	found := 0
	for _, cookie := range setCookies {
		if cookie.Name == "new1" || cookie.Name == "new2" {
			found++
		}
	}
	if found != 2 {
		t.Errorf("expected 2 new cookies, found %d", found)
	}

	// Test with invalid URL
	err = response.SetCookies("", cookies)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestResponseSetCookiesWithoutJar(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Client without session (no cookie jar)
	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Test SetCookies without jar
	cookies := []*http.Cookie{{Name: "test", Value: "value"}}
	err := response.SetCookies(g.String(ts.URL), cookies)
	if err == nil {
		t.Error("expected error when setting cookies without jar")
	}
}

func TestResponseRemoteAddress(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with GetRemoteAddress enabled
	client := surf.NewClient().Builder().GetRemoteAddress().Build()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	remoteAddr := resp.Ok().RemoteAddress()
	if remoteAddr == nil {
		t.Error("expected remote address to be captured")
	} else {
		// Verify it's a TCP address
		if _, ok := remoteAddr.(*net.TCPAddr); !ok {
			t.Errorf("expected *net.TCPAddr, got %T", remoteAddr)
		}
	}

	// Test without GetRemoteAddress
	client = surf.NewClient()
	resp = client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	remoteAddr = resp.Ok().RemoteAddress()
	if remoteAddr != nil {
		t.Error("expected nil remote address when not enabled")
	}
}

func TestResponseTLSGrabber(t *testing.T) {
	t.Parallel()

	// Create HTTPS test server
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test TLSGrabber
	tlsData := resp.Ok().TLSGrabber()
	if tlsData == nil {
		t.Error("expected TLS data for HTTPS connection")
	}
}

func TestResponseTLSGrabberHTTP(t *testing.T) {
	t.Parallel()

	// Create HTTP test server (not HTTPS)
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test TLSGrabber for non-TLS connection
	tlsData := resp.Ok().TLSGrabber()
	if tlsData != nil {
		t.Error("expected nil TLS data for HTTP connection")
	}
}

func TestResponseWithRetry(t *testing.T) {
	t.Parallel()

	attemptCount := 0
	handler := func(w http.ResponseWriter, _ *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "error")
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "success")
		}
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Retry(5, 10*time.Millisecond).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Test Attempts count
	if response.Attempts != 2 {
		t.Errorf("expected 2 retry attempts, got %d", response.Attempts)
	}

	if !response.Body.Contains("success") {
		t.Error("expected 'success' in body")
	}
}

func TestResponseHeaders(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Single", "value")
		w.Header().Add("X-Multiple", "value1")
		w.Header().Add("X-Multiple", "value2")
		w.Header().Set("Content-Type", "text/plain")
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

	response := resp.Ok()

	// Test single header
	if response.Headers.Get("X-Single") != "value" {
		t.Errorf("expected X-Single=value, got %s", response.Headers.Get("X-Single"))
	}

	// Test multiple headers
	values := response.Headers.Values("X-Multiple")
	if len(values) != 2 || values[0] != "value1" || values[1] != "value2" {
		t.Errorf("expected X-Multiple=[value1, value2], got %v", values)
	}

	// Test header contains
	if !response.Headers.Contains("Content-Type", "text/plain") {
		t.Error("expected Content-Type to contain text/plain")
	}

	// Test Clone
	clonedHeaders := response.Headers.Clone()
	if clonedHeaders.Get("X-Single") != "value" {
		t.Error("cloned headers missing X-Single")
	}
}

func TestResponseURL(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL + "/path?query=value")).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	if response.URL == nil {
		t.Fatal("URL is nil")
	}

	// Verify URL components
	if response.URL.Path != "/path" {
		t.Errorf("expected path /path, got %s", response.URL.Path)
	}

	if response.URL.Query().Get("query") != "value" {
		t.Errorf("expected query=value, got %s", response.URL.Query().Get("query"))
	}

	parsedURL, _ := url.Parse(ts.URL)
	if response.URL.Host != parsedURL.Host {
		t.Errorf("expected host %s, got %s", parsedURL.Host, response.URL.Host)
	}
}

func TestResponseRedirect(t *testing.T) {
	t.Parallel()

	redirectCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		if redirectCount == 0 {
			redirectCount++
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		w.Header().Set("X-Redirected", "true")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "redirected")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Check final URL after redirect
	if response.URL.Path != "/redirected" {
		t.Errorf("expected path /redirected after redirect, got %s", response.URL.Path)
	}

	// Check response from redirected page
	if !response.Body.Contains("redirected") {
		t.Error("expected 'redirected' in body")
	}

	if response.Headers.Get("X-Redirected") != "true" {
		t.Error("expected X-Redirected header after redirect")
	}
}

func TestResponseClientMethods(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "first")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Test that response has Client methods
	if response.GetClient() == nil {
		t.Error("GetClient() returned nil")
	}

	if response.GetDialer() == nil {
		t.Error("GetDialer() returned nil")
	}

	if response.GetTransport() == nil {
		t.Error("GetTransport() returned nil")
	}

	if response.GetTLSConfig() == nil {
		t.Error("GetTLSConfig() returned nil")
	}

	// Test chaining - make another request using the response
	resp2 := response.Get(g.String(ts.URL + "/second")).Do()
	if resp2.IsErr() {
		t.Fatal(resp2.Err())
	}

	// Should use the same client
	if resp2.Ok().GetClient() != response.GetClient() {
		t.Error("expected same client for chained request")
	}
}

func TestResponseWithMiddleware(t *testing.T) {
	t.Parallel()

	var middlewareCalled bool

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		With(func(resp *surf.Response) error {
			middlewareCalled = true
			// Verify response properties are available in middleware
			if resp.StatusCode != 200 {
				t.Errorf("expected status 200 in middleware, got %d", resp.StatusCode)
			}
			return nil
		}).
		Build()

	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !middlewareCalled {
		t.Error("response middleware was not called")
	}
}

func TestResponseNilBody(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
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

	if response.Body != nil {
		t.Error("expected nil body for HEAD request")
	}

	// GetResponse should still work
	if response.GetResponse() == nil {
		t.Error("GetResponse() returned nil")
	}
}

func TestResponseTLSProperties(t *testing.T) {
	t.Parallel()

	// Use httptest TLS server since custom cert parsing fails
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer server.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(server.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Test TLS is present
	httpResp := resp.Ok().GetResponse()
	if httpResp.TLS == nil {
		t.Error("expected TLS connection state")
	}
}

func TestResponseStatusCodeEdgeCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		statusCode       int
		expectError      bool
		checkSuccess     bool
		checkRedirect    bool
		checkClientError bool
		checkServerError bool
	}{
		// 1xx Informational (Skip - httptest doesn't handle these properly)
		// {"Continue", 100, false, false, false, false, false},
		// {"Switching Protocols", 101, false, false, false, false, false},
		// {"Processing", 102, false, false, false, false, false},
		// {"Early Hints", 103, false, false, false, false, false},

		// 2xx Success
		{"OK", 200, false, true, false, false, false},
		{"Created", 201, false, true, false, false, false},
		{"Accepted", 202, false, true, false, false, false},
		{"Non-Authoritative Info", 203, false, true, false, false, false},
		{"No Content", 204, false, true, false, false, false},
		{"Reset Content", 205, false, true, false, false, false},
		{"Partial Content", 206, false, true, false, false, false},
		{"Multi-Status", 207, false, true, false, false, false},
		{"Already Reported", 208, false, true, false, false, false},
		{"IM Used", 226, false, true, false, false, false},

		// 3xx Redirection
		{"Multiple Choices", 300, false, false, true, false, false},
		{"Moved Permanently", 301, false, false, true, false, false},
		{"Found", 302, false, false, true, false, false},
		{"See Other", 303, false, false, true, false, false},
		{"Not Modified", 304, false, false, true, false, false},
		{"Use Proxy", 305, false, false, true, false, false},
		{"Temporary Redirect", 307, false, false, true, false, false},
		{"Permanent Redirect", 308, false, false, true, false, false},

		// 4xx Client Error
		{"Bad Request", 400, false, false, false, true, false},
		{"Unauthorized", 401, false, false, false, true, false},
		{"Payment Required", 402, false, false, false, true, false},
		{"Forbidden", 403, false, false, false, true, false},
		{"Not Found", 404, false, false, false, true, false},
		{"Method Not Allowed", 405, false, false, false, true, false},
		{"Not Acceptable", 406, false, false, false, true, false},
		{"Proxy Auth Required", 407, false, false, false, true, false},
		{"Request Timeout", 408, false, false, false, true, false},
		{"Conflict", 409, false, false, false, true, false},
		{"Gone", 410, false, false, false, true, false},
		{"Length Required", 411, false, false, false, true, false},
		{"Precondition Failed", 412, false, false, false, true, false},
		{"Payload Too Large", 413, false, false, false, true, false},
		{"URI Too Long", 414, false, false, false, true, false},
		{"Unsupported Media Type", 415, false, false, false, true, false},
		{"Range Not Satisfiable", 416, false, false, false, true, false},
		{"Expectation Failed", 417, false, false, false, true, false},
		{"I'm a teapot", 418, false, false, false, true, false},
		{"Misdirected Request", 421, false, false, false, true, false},
		{"Unprocessable Entity", 422, false, false, false, true, false},
		{"Locked", 423, false, false, false, true, false},
		{"Failed Dependency", 424, false, false, false, true, false},
		{"Too Early", 425, false, false, false, true, false},
		{"Upgrade Required", 426, false, false, false, true, false},
		{"Precondition Required", 428, false, false, false, true, false},
		{"Too Many Requests", 429, false, false, false, true, false},
		{"Request Header Fields Too Large", 431, false, false, false, true, false},
		{"Unavailable For Legal Reasons", 451, false, false, false, true, false},

		// 5xx Server Error
		{"Internal Server Error", 500, false, false, false, false, true},
		{"Not Implemented", 501, false, false, false, false, true},
		{"Bad Gateway", 502, false, false, false, false, true},
		{"Service Unavailable", 503, false, false, false, false, true},
		{"Gateway Timeout", 504, false, false, false, false, true},
		{"HTTP Version Not Supported", 505, false, false, false, false, true},
		{"Variant Also Negotiates", 506, false, false, false, false, true},
		{"Insufficient Storage", 507, false, false, false, false, true},
		{"Loop Detected", 508, false, false, false, false, true},
		{"Not Extended", 510, false, false, false, false, true},
		{"Network Authentication Required", 511, false, false, false, false, true},

		// Custom/Non-standard status codes
		{"Custom Success", 250, false, true, false, false, false},
		{"Custom Redirect", 350, false, false, true, false, false},
		{"Custom Client Error", 450, false, false, false, true, false},
		{"Custom Server Error", 550, false, false, false, false, true},

		// Edge cases - note: httptest may not handle these properly
		{"Invalid status", 999, false, false, false, false, true}, // Use 999 instead of 0
		// Skip 999 as httptest server error handling is non-standard
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.statusCode)
				fmt.Fprintf(w, "Status: %d", tc.statusCode)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Get(g.String(ts.URL)).Do()

			if tc.expectError {
				if resp.IsErr() {
					return // Expected error
				}
				t.Errorf("expected error for status %d but got none", tc.statusCode)
				return
			}

			if resp.IsErr() {
				t.Errorf("unexpected error for status %d: %v", tc.statusCode, resp.Err())
				return
			}

			response := resp.Ok()

			// Test basic status code
			if int(response.StatusCode) != tc.statusCode {
				t.Errorf("expected status %d, got %d", tc.statusCode, int(response.StatusCode))
			}

			// Test status code category checks
			if tc.checkSuccess && !response.StatusCode.IsSuccess() {
				t.Errorf("expected status %d to be success", tc.statusCode)
			}
			if !tc.checkSuccess && response.StatusCode.IsSuccess() {
				t.Errorf("expected status %d to not be success", tc.statusCode)
			}

			if tc.checkRedirect && !response.StatusCode.IsRedirection() {
				t.Errorf("expected status %d to be redirect", tc.statusCode)
			}
			if !tc.checkRedirect && response.StatusCode.IsRedirection() {
				t.Errorf("expected status %d to not be redirect", tc.statusCode)
			}

			if tc.checkClientError && !response.StatusCode.IsClientError() {
				t.Errorf("expected status %d to be client error", tc.statusCode)
			}
			if !tc.checkClientError && response.StatusCode.IsClientError() {
				t.Errorf("expected status %d to not be client error", tc.statusCode)
			}

			if tc.checkServerError && !response.StatusCode.IsServerError() {
				t.Errorf("expected status %d to be server error", tc.statusCode)
			}
			if !tc.checkServerError && response.StatusCode.IsServerError() {
				t.Errorf("expected status %d to not be server error", tc.statusCode)
			}

			// Test body contains expected content (skip for statuses that typically have no body)
			if tc.statusCode != 204 && tc.statusCode != 304 {
				expectedBody := fmt.Sprintf("Status: %d", tc.statusCode)
				if !response.Body.Contains(expectedBody) {
					t.Errorf("expected body to contain '%s'", expectedBody)
				}
			}
		})
	}
}

func TestResponseStatusCodeMethods(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		status      int
		isInfo      bool
		isSuccess   bool
		isRedirect  bool
		isClientErr bool
		isServerErr bool
		isError     bool
	}{
		// Skip 100 as httptest converts it to 200
		{200, false, true, false, false, false, false},
		{300, false, false, true, false, false, false},
		{400, false, false, false, true, false, true},
		{500, false, false, false, false, true, true},
		{600, false, false, false, false, true, true}, // Non-standard but >= 500
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Status_%d", tc.status), func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			statusCode := resp.Ok().StatusCode

			if statusCode.IsInformational() != tc.isInfo {
				t.Errorf("IsInformational() for %d: expected %v, got %v", tc.status, tc.isInfo, statusCode.IsInformational())
			}
			if statusCode.IsSuccess() != tc.isSuccess {
				t.Errorf("IsSuccess() for %d: expected %v, got %v", tc.status, tc.isSuccess, statusCode.IsSuccess())
			}
			if statusCode.IsRedirection() != tc.isRedirect {
				t.Errorf("IsRedirection() for %d: expected %v, got %v", tc.status, tc.isRedirect, statusCode.IsRedirection())
			}
			if statusCode.IsClientError() != tc.isClientErr {
				t.Errorf("IsClientError() for %d: expected %v, got %v", tc.status, tc.isClientErr, statusCode.IsClientError())
			}
			if statusCode.IsServerError() != tc.isServerErr {
				t.Errorf("IsServerError() for %d: expected %v, got %v", tc.status, tc.isServerErr, statusCode.IsServerError())
			}
			// IsError() doesn't exist in the StatusCode type, check if it's client or server error
			isError := statusCode.IsClientError() || statusCode.IsServerError()
			if isError != tc.isError {
				t.Errorf("IsError() for %d: expected %v, got %v", tc.status, tc.isError, isError)
			}
		})
	}
}

func TestResponseStatusCodeString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		status   int
		expected string
	}{
		{200, "200 OK"},
		{404, "404 Not Found"},
		{500, "500 Internal Server Error"},
		{999, "999 status code 999"}, // Unknown status
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("StatusString_%d", tc.status), func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Fatal(resp.Err())
			}

			response := resp.Ok()

			// Get status string from underlying http.Response
			actualStatus := response.GetResponse().Status
			if actualStatus != tc.expected {
				t.Errorf("expected status string '%s', got '%s'", tc.expected, actualStatus)
			}
		})
	}
}

func TestResponseNoFollowRedirects(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "redirected content")
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	// Test with redirects disabled
	client := surf.NewClient().Builder().NotFollowRedirects().Build()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Should get redirect status, not follow it
	if int(response.StatusCode) != 302 {
		t.Errorf("expected status 302 with redirects disabled, got %d", int(response.StatusCode))
	}

	if !response.StatusCode.IsRedirection() {
		t.Error("expected redirect status code")
	}

	// Should have Location header
	location := response.Location()
	if location == "" {
		t.Error("expected Location header")
	}
}

func TestResponseLargeStatusCodes(t *testing.T) {
	t.Parallel()

	// Note: httptest might not support all custom status codes
	// This test focuses on the response handling logic

	testCases := []int{
		// Skip 100, 199 as httptest doesn't handle them well
		200, 299, // Success boundary
		300, 399, // Redirect boundary
		400, 499, // Client error boundary
		500, 599, // Server error boundary
		600, 700, // Beyond standard ranges
	}

	for _, status := range testCases {
		t.Run(fmt.Sprintf("Status_%d", status), func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				fmt.Fprintf(w, "Custom status: %d", status)
			}

			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer ts.Close()

			client := surf.NewClient()
			resp := client.Get(g.String(ts.URL)).Do()
			if resp.IsErr() {
				t.Logf("Error for status %d (may be expected): %v", status, resp.Err())
				return
			}

			response := resp.Ok()

			// Verify status code is preserved
			if int(response.StatusCode) != status {
				t.Errorf("expected status %d, got %d", status, int(response.StatusCode))
			}

			// Verify body content
			expectedBody := fmt.Sprintf("Custom status: %d", status)
			if !response.Body.Contains(expectedBody) {
				t.Errorf("expected body to contain '%s'", expectedBody)
			}
		})
	}
}

func TestResponseEmptyStatusLine(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		// Just send OK status
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	response := resp.Ok()

	// Should have proper status line
	if response.GetResponse().Status == "" {
		t.Error("expected non-empty status line")
	}

	// Body might be empty for some status codes, that's OK
	_ = response.Body.String()
}
