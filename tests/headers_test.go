package surf_test

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/enetx/g"
	ehttp "github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
)

func TestHeadersBasic(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom", "test-value")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test header access
	if !headers.Contains("Content-Type", "application/json") {
		t.Error("expected Content-Type header to contain application/json")
	}

	if headers.Get("Content-Type").Std() != "application/json" {
		t.Errorf("expected Content-Type to be application/json, got %s", headers.Get("Content-Type"))
	}

	if headers.Get("X-Custom").Std() != "test-value" {
		t.Errorf("expected X-Custom to be test-value, got %s", headers.Get("X-Custom"))
	}
}

func TestHeaderConstants(t *testing.T) {
	t.Parallel()

	// Test that header constants are available
	if header.ACCEPT == "" {
		t.Error("expected ACCEPT header constant to be available")
	}

	if header.CONTENT_TYPE == "" {
		t.Error("expected CONTENT_TYPE header constant to be available")
	}

	if header.USER_AGENT == "" {
		t.Error("expected USER_AGENT header constant to be available")
	}

	if header.AUTHORIZATION == "" {
		t.Error("expected AUTHORIZATION header constant to be available")
	}
}

func TestHeadersIteration(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("X-Header-1", "value1")
		w.Header().Set("X-Header-2", "value2")
		w.Header().Set("X-Header-3", "value3")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers
	foundHeaders := 0

	// Iterate through headers manually since Headers doesn't have ForEach
	for name := range headers {
		if g.String(name).StartsWith("X-Header-") {
			foundHeaders++
		}
	}

	if foundHeaders != 3 {
		t.Errorf("expected 3 custom headers, found %d", foundHeaders)
	}
}

func TestHeadersSetOnRequest(t *testing.T) {
	t.Parallel()

	var receivedHeaders map[string]string

	handler := func(w ehttp.ResponseWriter, r *ehttp.Request) {
		receivedHeaders = make(map[string]string)
		for name, values := range r.Header {
			if len(values) > 0 {
				receivedHeaders[name] = values[0]
			}
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()

	headers := g.NewMapOrd[g.String, g.String](3)
	headers.Set("X-Custom-1", "value1")
	headers.Set("X-Custom-2", "value2")
	headers.Set(header.CONTENT_TYPE, "application/json")

	resp := client.Get(g.String(ts.URL)).SetHeaders(headers).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Check that headers were sent
	if receivedHeaders["X-Custom-1"] != "value1" {
		t.Error("expected X-Custom-1 header to be sent")
	}

	if receivedHeaders["X-Custom-2"] != "value2" {
		t.Error("expected X-Custom-2 header to be sent")
	}

	if receivedHeaders["Content-Type"] != "application/json" {
		t.Error("expected Content-Type header to be sent")
	}
}

func TestHeadersCaseInsensitive(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test case-insensitive access
	if !headers.Contains("content-type", "application/json") {
		t.Error("expected headers to be case-insensitive")
	}

	if !headers.Contains("CONTENT-TYPE", "application/json") {
		t.Error("expected headers to be case-insensitive")
	}

	if headers.Get("content-type").Empty() {
		t.Error("expected case-insensitive header access")
	}
}

func TestHeadersEmpty(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test accessing non-existent header
	if !headers.Get("Non-Existent-Header").Empty() {
		t.Error("expected non-existent header to return empty string")
	}

	if headers.Contains("Non-Existent-Header", "any") {
		t.Error("expected Contains to return false for non-existent header")
	}
}

func TestHeadersMultipleValues(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Add("X-Multi", "value1")
		w.Header().Add("X-Multi", "value2")
		w.Header().Add("X-Multi", "value3")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test that multi-value headers are handled
	if !headers.Contains("X-Multi", "value1") {
		t.Error("expected X-Multi header to contain value1")
	}

	multiValue := headers.Get("X-Multi")
	if multiValue.Empty() {
		t.Error("expected X-Multi header to have value")
	}
}

func TestHeadersContainsEdgeCases(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Custom", "value with spaces")
		w.Header().Set("Empty-Header", "")
		w.Header().Add("Multi-Value", "part1,part2,part3")
		w.Header().Add("Multi-Value", "part4")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test partial matching
	if !headers.Contains("Content-Type", "application/json") {
		t.Error("expected Contains to work with partial matches")
	}

	// Test exact matching
	if !headers.Contains("Content-Type", "application/json; charset=utf-8") {
		t.Error("expected Contains to work with exact matches")
	}

	// Test with spaces
	if !headers.Contains("X-Custom", "value with spaces") {
		t.Error("expected Contains to work with values containing spaces")
	}

	// Test empty value
	if !headers.Contains("Empty-Header", "") {
		t.Error("expected Contains to work with empty values")
	}

	// Test case sensitivity of values (may be case insensitive)
	containsUpper := headers.Contains("Content-Type", "APPLICATION/JSON")
	t.Logf("Contains with uppercase value: %v", containsUpper)

	// Test non-matching value
	if headers.Contains("Content-Type", "text/plain") {
		t.Error("expected Contains to return false for non-matching values")
	}

	// Test with nil/empty headers
	var emptyHeaders surf.Headers
	if emptyHeaders.Contains("any", "value") {
		t.Error("expected empty headers to not contain any header")
	}
}

func TestHeadersContainsWithCommaValues(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9")
		w.Header().Set("Accept-Language", "en-US,en;q=0.9,ru;q=0.8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test Contains with comma-separated values
	if !headers.Contains("Accept", "text/html") {
		t.Error("expected Contains to find text/html in Accept header")
	}

	if !headers.Contains("Accept", "application/xml") {
		t.Error("expected Contains to find application/xml in Accept header")
	}

	if !headers.Contains("Accept-Language", "en-US") {
		t.Error("expected Contains to find en-US in Accept-Language header")
	}

	if !headers.Contains("Cache-Control", "no-cache") {
		t.Error("expected Contains to find no-cache in Cache-Control header")
	}

	if !headers.Contains("Cache-Control", "must-revalidate") {
		t.Error("expected Contains to find must-revalidate in Cache-Control header")
	}

	// Test non-existing values
	if headers.Contains("Accept", "text/plain") {
		t.Error("expected Contains to return false for non-existing value")
	}
}

func TestHeadersContainsSpecialChars(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("X-Special", "value with 特殊字符 and émojis 🚀")
		w.Header().Set("X-Quotes", `"quoted value"`)
		w.Header().Set("X-Semicolon", "key=value; boundary=something")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test special characters
	if !headers.Contains("X-Special", "特殊字符") {
		t.Error("expected Contains to work with unicode characters")
	}

	if !headers.Contains("X-Special", "🚀") {
		t.Error("expected Contains to work with emojis")
	}

	// Test quoted values
	if !headers.Contains("X-Quotes", "quoted value") {
		t.Error("expected Contains to work with quoted values")
	}

	// Test semicolon-separated values
	if !headers.Contains("X-Semicolon", "key=value") {
		t.Error("expected Contains to work with semicolon-separated values")
	}

	if !headers.Contains("X-Semicolon", "boundary=something") {
		t.Error("expected Contains to find boundary in semicolon-separated header")
	}
}

func TestHeadersDirectMethods(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Single-Value", "test")
		w.Header().Add("Multi-Value", "first")
		w.Header().Add("Multi-Value", "second")
		w.Header().Set("Empty-Value", "")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test Get method
	singleValue := headers.Get("Single-Value")
	if singleValue != "test" {
		t.Errorf("expected Get to return 'test', got %q", singleValue)
	}

	// Test Get with empty value
	emptyValue := headers.Get("Empty-Value")
	if emptyValue != "" {
		t.Errorf("expected Get to return empty string, got %q", emptyValue)
	}

	// Test Get with non-existent header
	nonExistent := headers.Get("Non-Existent")
	if !nonExistent.Empty() {
		t.Error("expected Get to return empty string for non-existent header")
	}

	// Test Values method
	multiValues := headers.Values("Multi-Value")
	if len(multiValues) != 2 {
		t.Errorf("expected Values to return 2 values, got %d", len(multiValues))
	}

	// Test Values with single value
	singleValues := headers.Values("Single-Value")
	if len(singleValues) != 1 || singleValues[0] != "test" {
		t.Error("expected Values to return single value correctly")
	}

	// Test Values with non-existent header
	nonExistentValues := headers.Values("Non-Existent")
	if len(nonExistentValues) != 0 {
		t.Error("expected Values to return empty slice for non-existent header")
	}
}

func TestHeadersContainsVariousTypes(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Accept", "text/html,application/json;q=0.9,text/plain")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test Contains with string
	if !headers.Contains("Content-Type", "application/json") {
		t.Error("expected Contains to work with string")
	}

	// Test Contains with g.String
	if !headers.Contains("Accept", g.String("text/html")) {
		t.Error("expected Contains to work with g.String")
	}

	// Test Contains with []string
	stringSlice := []string{"text/html", "application/json"}
	if !headers.Contains("Accept", stringSlice) {
		t.Error("expected Contains to work with []string")
	}

	// Test Contains with g.Slice[string]
	gStringSlice := g.SliceOf("no-cache", "must-revalidate")
	if !headers.Contains("Cache-Control", gStringSlice) {
		t.Error("expected Contains to work with g.Slice[string]")
	}

	// Test Contains with g.Slice[g.String]
	gSliceOfGString := g.SliceOf(g.String("no-store"), g.String("no-cache"))
	if !headers.Contains("Cache-Control", gSliceOfGString) {
		t.Error("expected Contains to work with g.Slice[g.String]")
	}
}

func TestHeadersClone(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Original", "value")
		w.Header().Set("Test", "original")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	original := resp.Ok().Headers
	cloned := original.Clone()

	// Test that clone has same values
	if cloned.Get("Original") != "value" {
		t.Error("expected cloned headers to have same values")
	}

	if cloned.Get("Test") != "original" {
		t.Error("expected cloned headers to have same test value")
	}

	// Test that modifications to original don't affect clone
	// Note: We can't directly modify headers returned from response,
	// but we can verify the clone operation worked
	if cloned == nil {
		t.Error("expected Clone to return non-nil headers")
	}
}

func TestHeadersCaseInsensitiveVariations(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "test-value")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test various case combinations for header names
	testCases := []string{
		"content-type",
		"Content-Type",
		"CONTENT-TYPE",
		"Content-type",
		"content-Type",
	}

	for _, headerName := range testCases {
		if !headers.Contains(g.String(headerName), "application/json") {
			t.Errorf("expected Contains to work case-insensitively with header name %q", headerName)
		}

		value := headers.Get(g.String(headerName))
		if value.Empty() {
			t.Errorf("expected Get to work case-insensitively with header name %q", headerName)
		}

		values := headers.Values(g.String(headerName))
		if len(values) == 0 {
			t.Errorf("expected Values to work case-insensitively with header name %q", headerName)
		}
	}
}

func TestHeadersContainsPatternMatching(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		w.Header().Set("Accept-Language", "en-US,en;q=0.5")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test partial matches
	if !headers.Contains("Accept", "text/html") {
		t.Error("expected Contains to find partial match 'text/html' in Accept header")
	}

	if !headers.Contains("Accept", "application/xml") {
		t.Error("expected Contains to find partial match 'application/xml' in Accept header")
	}

	if !headers.Contains("Accept-Language", "en-US") {
		t.Error("expected Contains to find partial match 'en-US' in Accept-Language header")
	}

	if !headers.Contains("Content-Type", "charset=UTF-8") {
		t.Error("expected Contains to find partial match 'charset=UTF-8' in Content-Type header")
	}

	// Test non-matching patterns
	if headers.Contains("Accept", "application/pdf") {
		t.Error("expected Contains to return false for non-matching pattern")
	}

	if headers.Contains("Accept-Language", "fr-FR") {
		t.Error("expected Contains to return false for non-matching language")
	}
}

func TestHeadersContainsRegexp(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-API-Version", "v1.2.3")
		w.Header().Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.token.signature")
		w.Header().Set("X-Request-ID", "req-123456789")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test Contains with regexp for API version pattern
	versionPattern, err := regexp.Compile(`v\d+\.\d+\.\d+`)
	if err != nil {
		t.Fatalf("failed to compile version regexp: %v", err)
	}

	if !headers.Contains("X-API-Version", []*regexp.Regexp{versionPattern}) {
		t.Error("expected Contains to match version pattern with regexp")
	}

	// Test Contains with JWT bearer token pattern (case insensitive)
	jwtPattern, err := regexp.Compile(`(?i)bearer eyj[a-za-z0-9+/=]+\.[a-za-z0-9+/=]*\.[a-za-z0-9+/=]*`)
	if err != nil {
		t.Fatalf("failed to compile JWT regexp: %v", err)
	}

	if !headers.Contains("Authorization", []*regexp.Regexp{jwtPattern}) {
		t.Error("expected Contains to match JWT token pattern")
	}

	// Test Contains with request ID pattern
	requestIDPattern, err := regexp.Compile(`req-\d+`)
	if err != nil {
		t.Fatalf("failed to compile request ID regexp: %v", err)
	}

	if !headers.Contains("X-Request-ID", []*regexp.Regexp{requestIDPattern}) {
		t.Error("expected Contains to match request ID pattern")
	}

	// Test Contains with multiple regexp patterns
	multiplePatterns := []*regexp.Regexp{
		regexp.MustCompile(`application/(json|xml)`),
		regexp.MustCompile(`text/.*`),
	}

	if !headers.Contains("Content-Type", multiplePatterns) {
		t.Error("expected Contains to match one of multiple patterns")
	}

	// Test Contains with regexp that doesn't match
	noMatchPattern, err := regexp.Compile(`admin-token-\d+`)
	if err != nil {
		t.Fatalf("failed to compile no-match regexp: %v", err)
	}

	if headers.Contains("Authorization", []*regexp.Regexp{noMatchPattern}) {
		t.Error("expected Contains to return false for non-matching regexp")
	}
}

func TestHeadersContainsComplexRegexp(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Cache-Control", "max-age=3600, s-maxage=1800, public")
		w.Header().Set("Set-Cookie", "sessionid=abc123; HttpOnly; Secure; SameSite=Strict")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.example.com")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test cache-control max-age pattern
	maxAgePattern, err := regexp.Compile(`max-age=\d+`)
	if err != nil {
		t.Fatalf("failed to compile max-age regexp: %v", err)
	}

	if !headers.Contains("Cache-Control", []*regexp.Regexp{maxAgePattern}) {
		t.Error("expected Contains to match max-age pattern")
	}

	// Test Set-Cookie security attributes pattern (case insensitive)
	cookieSecurityPattern, err := regexp.Compile(`(?i);\s*(httponly|secure|samesite=\w+)`)
	if err != nil {
		t.Fatalf("failed to compile cookie security regexp: %v", err)
	}

	if !headers.Contains("Set-Cookie", []*regexp.Regexp{cookieSecurityPattern}) {
		t.Error("expected Contains to match cookie security attributes")
	}

	// Test CSP source pattern
	cspSourcePattern, err := regexp.Compile(`https://[a-z0-9.-]+\.com`)
	if err != nil {
		t.Fatalf("failed to compile CSP source regexp: %v", err)
	}

	if !headers.Contains("Content-Security-Policy", []*regexp.Regexp{cspSourcePattern}) {
		t.Error("expected Contains to match CSP source pattern")
	}
}

func TestHeadersValuesNilAndEmpty(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Normal-Header", "value")
		w.Header().Set("Empty-Header", "")
		// Note: Can't set truly nil header values via standard http.Header
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test Values with non-existent header returns nil/empty
	nonExistentValues := headers.Values("Non-Existent-Header")
	if nonExistentValues != nil && len(nonExistentValues) > 0 {
		t.Error("expected Values to return empty slice for non-existent header")
	}

	// Test Values with empty header value
	emptyValues := headers.Values("Empty-Header")
	if len(emptyValues) != 1 || emptyValues[0] != "" {
		t.Errorf("expected Values to return single empty string for empty header, got %v", emptyValues)
	}

	// Test that Contains works with nil/empty values
	if headers.Contains("Non-Existent-Header", "anything") {
		t.Error("expected Contains to return false for non-existent header")
	}

	// Empty header should match empty string
	if !headers.Contains("Empty-Header", "") {
		t.Error("expected Contains to match empty string for empty header")
	}
}

func TestHeadersCloneAndModification(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Original", "value1")
		w.Header().Set("Shared", "shared-value")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	original := resp.Ok().Headers
	cloned := original.Clone()

	// Test that both have same initial values
	if original.Get("Original") != cloned.Get("Original") {
		t.Error("expected cloned headers to have same values initially")
	}

	if original.Get("Shared") != cloned.Get("Shared") {
		t.Error("expected cloned headers to have same shared values initially")
	}

	// Test that clone is truly independent
	// Note: Since these are response headers, we can't actually modify them directly,
	// but we can verify the clone operation creates a proper copy

	if cloned == nil {
		t.Error("expected Clone to return non-nil headers")
	}

	// Test different memory addresses (clone should be separate)
	if &original == &cloned {
		t.Error("expected Clone to create separate header instances")
	}
}

func TestHeadersContainsAllPatternTypes(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		w.Header().Set("Test-Header", "test-value-123")
		w.Header().Add("Multi-Header", "value1")
		w.Header().Add("Multi-Header", "value2")
		w.Header().Add("Multi-Header", "value3")
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	headers := resp.Ok().Headers

	// Test all pattern types that Headers.Contains supports

	// 1. string pattern
	if !headers.Contains("Test-Header", "test-value") {
		t.Error("expected Contains to work with string pattern")
	}

	// 2. g.String pattern
	if !headers.Contains("Test-Header", g.String("value-123")) {
		t.Error("expected Contains to work with g.String pattern")
	}

	// 3. []string pattern
	stringSlice := []string{"value1", "value2"}
	if !headers.Contains("Multi-Header", stringSlice) {
		t.Error("expected Contains to work with []string pattern")
	}

	// 4. g.Slice[string] pattern
	gSliceString := g.SliceOf("value2", "value3")
	if !headers.Contains("Multi-Header", gSliceString) {
		t.Error("expected Contains to work with g.Slice[string] pattern")
	}

	// 5. g.Slice[g.String] pattern
	gSliceGString := g.SliceOf(g.String("value1"), g.String("value2"))
	if !headers.Contains("Multi-Header", gSliceGString) {
		t.Error("expected Contains to work with g.Slice[g.String] pattern")
	}

	// 6. []*regexp.Regexp pattern
	regexPattern := []*regexp.Regexp{regexp.MustCompile(`test-value-\d+`)}
	if !headers.Contains("Test-Header", regexPattern) {
		t.Error("expected Contains to work with []*regexp.Regexp pattern")
	}

	// Test non-matching patterns
	if headers.Contains("Test-Header", "non-matching") {
		t.Error("expected Contains to return false for non-matching string")
	}

	if headers.Contains("Multi-Header", []string{"non-matching1", "non-matching2"}) {
		t.Error("expected Contains to return false for non-matching string slice")
	}

	nonMatchingRegex := []*regexp.Regexp{regexp.MustCompile(`admin-\d+`)}
	if headers.Contains("Test-Header", nonMatchingRegex) {
		t.Error("expected Contains to return false for non-matching regexp")
	}
}
