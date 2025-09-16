package surf_test

import (
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/enetx/g"
	ehttp "github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestCookiesBasic(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "test-cookie",
			Value: "test-value",
		})
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "another-cookie",
			Value: "another-value",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	// Test cookie access by searching through the slice
	if !cookies.Contains("test-cookie") {
		t.Error("expected test-cookie to be present")
	}

	// Find test-cookie value manually
	var foundTestCookie bool
	for _, cookie := range cookies {
		if cookie.Name == "test-cookie" {
			if cookie.Value != "test-value" {
				t.Errorf("expected test-cookie value to be test-value, got %s", cookie.Value)
			}
			foundTestCookie = true
			break
		}
	}

	if !foundTestCookie {
		t.Error("test-cookie not found in cookies")
	}

	if !cookies.Contains("another-cookie") {
		t.Error("expected another-cookie to be present")
	}
}

func TestCookiesWithAttributes(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:     "secure-cookie",
			Value:    "secure-value",
			Path:     "/test",
			Domain:   "127.0.0.1",
			Expires:  time.Now().Add(time.Hour),
			Secure:   true,
			HttpOnly: true,
			SameSite: ehttp.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	if !cookies.Contains("secure-cookie") {
		t.Error("expected secure-cookie to be present")
	}

	// Find secure-cookie manually
	var secureCookie *ehttp.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "secure-cookie" {
			secureCookie = cookie
			break
		}
	}

	if secureCookie == nil {
		t.Fatal("secure-cookie not found")
	}

	if secureCookie.Value != "secure-value" {
		t.Errorf("expected cookie value to be secure-value, got %s", secureCookie.Value)
	}

	// Test cookie attributes
	if secureCookie.Path != "/test" {
		t.Errorf("expected cookie path to be /test, got %s", secureCookie.Path)
	}

	if secureCookie.Domain != "127.0.0.1" {
		t.Errorf("expected cookie domain to be 127.0.0.1, got %s", secureCookie.Domain)
	}
}

func TestCookiesIteration(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		for i := 1; i <= 5; i++ {
			ehttp.SetCookie(w, &ehttp.Cookie{
				Name:  fmt.Sprintf("cookie-%d", i),
				Value: fmt.Sprintf("value-%d", i),
			})
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies
	cookieCount := 0

	for _, cookie := range cookies {
		if g.String(cookie.Name).StartsWith("cookie-") {
			cookieCount++
		}
	}

	if cookieCount != 5 {
		t.Errorf("expected 5 cookies, found %d", cookieCount)
	}
}

func TestCookiesSent(t *testing.T) {
	t.Parallel()

	var receivedCookies []*ehttp.Cookie

	handler := func(w ehttp.ResponseWriter, r *ehttp.Request) {
		receivedCookies = r.Cookies()
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()

	// First request - set cookies manually
	cookies := []*ehttp.Cookie{
		{Name: "custom-cookie-1", Value: "value1"},
		{Name: "custom-cookie-2", Value: "value2"},
	}

	firstReq := client.Get(g.String(ts.URL)).AddCookies(cookies...)

	resp := firstReq.Do()
	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	// Check that cookies were sent
	if len(receivedCookies) != 2 {
		t.Errorf("expected 2 cookies to be sent, got %d", len(receivedCookies))
	}

	foundCookie1 := false
	foundCookie2 := false
	for _, cookie := range receivedCookies {
		if cookie.Name == "custom-cookie-1" && cookie.Value == "value1" {
			foundCookie1 = true
		}
		if cookie.Name == "custom-cookie-2" && cookie.Value == "value2" {
			foundCookie2 = true
		}
	}

	if !foundCookie1 {
		t.Error("expected custom-cookie-1 to be sent")
	}
	if !foundCookie2 {
		t.Error("expected custom-cookie-2 to be sent")
	}
}

func TestCookiesSessionPersistence(t *testing.T) {
	t.Parallel()

	step := 0
	var receivedCookies []*ehttp.Cookie

	handler := func(w ehttp.ResponseWriter, r *ehttp.Request) {
		step++
		receivedCookies = r.Cookies()

		if step == 1 {
			// First request - set a cookie
			ehttp.SetCookie(w, &ehttp.Cookie{
				Name:  "session-cookie",
				Value: "session-value",
			})
		}
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()

	// First request
	resp1 := client.Get(g.String(ts.URL)).Do()
	if resp1.IsErr() {
		t.Fatal(resp1.Err())
	}

	// Second request - cookie should be sent automatically
	resp2 := client.Get(g.String(ts.URL)).Do()
	if resp2.IsErr() {
		t.Fatal(resp2.Err())
	}

	// Check that session cookie was sent in second request
	foundSessionCookie := false
	for _, cookie := range receivedCookies {
		if cookie.Name == "session-cookie" && cookie.Value == "session-value" {
			foundSessionCookie = true
			break
		}
	}

	if !foundSessionCookie {
		t.Error("expected session cookie to persist and be sent in second request")
	}
}

func TestCookiesEmpty(t *testing.T) {
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

	cookies := resp.Ok().Cookies

	// Test accessing non-existent cookie
	if cookies.Contains("non-existent-cookie") {
		t.Error("expected Contains to return false for non-existent cookie")
	}

	// Check that no cookie with this name exists
	foundNonExistent := false
	for _, cookie := range cookies {
		if cookie.Name == "non-existent-cookie" {
			foundNonExistent = true
			break
		}
	}

	if foundNonExistent {
		t.Error("expected non-existent cookie to not be found")
	}
}

func TestCookiesSpecialChars(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "special-cookie",
			Value: "value with spaces and 特殊字符",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	if !cookies.Contains("special-cookie") {
		t.Error("expected special-cookie to be present")
	}

	// Find special cookie manually
	var specialCookie *ehttp.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "special-cookie" {
			specialCookie = cookie
			break
		}
	}

	if specialCookie == nil || specialCookie.Value == "" {
		t.Error("expected special cookie to have a value")
	}
}

func TestCookiesContainsEdgeCases(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		// Set cookies with various edge cases
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "",
			Value: "empty-name",
		})
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "empty-value",
			Value: "",
		})
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "normal",
			Value: "normal-value",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	// Test Contains with empty string
	containsEmpty := cookies.Contains("")
	t.Logf("Contains empty string: %v", containsEmpty)

	// Test Contains with normal cookie
	if !cookies.Contains("normal") {
		t.Error("expected normal cookie to be present")
	}

	// Test Contains with empty value cookie
	if !cookies.Contains("empty-value") {
		t.Error("expected empty-value cookie to be present")
	}

	// Test Contains with nil/empty cookies slice
	var emptyCookies surf.Cookies
	if emptyCookies.Contains("any") {
		t.Error("expected empty cookies to not contain any cookie")
	}
}

func TestCookiesMultipleSameName(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		// Set multiple cookies with same name but different paths
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "duplicate",
			Value: "value1",
			Path:  "/",
		})
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "duplicate",
			Value: "value2",
			Path:  "/api",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	// Contains should return true if at least one cookie with the name exists
	if !cookies.Contains("duplicate") {
		t.Error("expected duplicate cookie to be present")
	}

	// Count how many cookies with name "duplicate" exist
	count := 0
	for _, cookie := range cookies {
		if cookie.Name == "duplicate" {
			count++
		}
	}

	if count < 1 {
		t.Error("expected at least one duplicate cookie")
	}
}

func TestCookiesContainsMethod(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "test-cookie",
			Value: "test-value",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	// Test Contains with string
	if !cookies.Contains("test-cookie") {
		t.Error("expected Contains to work with string pattern")
	}

	// Test Contains with g.String
	if !cookies.Contains(g.String("test-cookie")) {
		t.Error("expected Contains to work with g.String pattern")
	}

	// Test Contains with non-existent cookie
	if cookies.Contains("non-existent") {
		t.Error("expected Contains to return false for non-existent cookie")
	}
}

func TestCookiesContainsRegexp(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "session-id",
			Value: "abc123def",
		})
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "user-pref",
			Value: "dark-theme",
		})
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "auth-token",
			Value: "bearer-xyz789",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	// Test Contains with regexp for session ID pattern
	sessionPattern, err := regexp.Compile(`session-id=[a-z0-9]+`)
	if err != nil {
		t.Fatalf("failed to compile regexp: %v", err)
	}

	if !cookies.Contains(sessionPattern) {
		t.Error("expected Contains to match session-id pattern with regexp")
	}

	// Test Contains with regexp for auth token
	authPattern, err := regexp.Compile(`auth-token=bearer-[a-z0-9]+`)
	if err != nil {
		t.Fatalf("failed to compile auth regexp: %v", err)
	}

	if !cookies.Contains(authPattern) {
		t.Error("expected Contains to match auth-token pattern with regexp")
	}

	// Test Contains with regexp that doesn't match
	noMatchPattern, err := regexp.Compile(`admin-session=[0-9]+`)
	if err != nil {
		t.Fatalf("failed to compile no-match regexp: %v", err)
	}

	if cookies.Contains(noMatchPattern) {
		t.Error("expected Contains to return false for non-matching regexp")
	}

	// Test with case-insensitive regexp
	caseInsensitivePattern, err := regexp.Compile(`(?i)USER-PREF=.*THEME`)
	if err != nil {
		t.Fatalf("failed to compile case-insensitive regexp: %v", err)
	}

	if !cookies.Contains(caseInsensitivePattern) {
		t.Error("expected Contains to match case-insensitive pattern")
	}
}

func TestCookiesContainsPatternTypes(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "TestCookie",
			Value: "TestValue",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	// Test case sensitivity - cookies.Contains() makes everything lowercase
	if !cookies.Contains("testcookie") {
		t.Error("expected Contains to work case-insensitively with string")
	}

	if !cookies.Contains("TESTCOOKIE") {
		t.Error("expected Contains to work case-insensitively with uppercase string")
	}

	// Test with g.String case sensitivity
	if !cookies.Contains(g.String("testvalue")) {
		t.Error("expected Contains to work case-insensitively with g.String")
	}

	if !cookies.Contains(g.String("TESTVALUE")) {
		t.Error("expected Contains to work case-insensitively with uppercase g.String")
	}
}

func TestCookiesContainsEmptyAndNil(t *testing.T) {
	t.Parallel()

	// Test with empty cookies
	var emptyCookies surf.Cookies

	if emptyCookies.Contains("any-pattern") {
		t.Error("expected Contains to return false for empty cookies")
	}

	if emptyCookies.Contains(g.String("any-pattern")) {
		t.Error("expected Contains to return false for empty cookies with g.String")
	}

	pattern, _ := regexp.Compile(`.*`)
	if emptyCookies.Contains(pattern) {
		t.Error("expected Contains to return false for empty cookies with regexp")
	}

	// Note: We can't test nil cookies pointer since (*Cookies).Contains
	// expects a non-nil receiver - this would require changing the method signature
}

func TestCookiesContainsPartialMatches(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:     "complex-cookie",
			Value:    "complex-value-with-dashes",
			Path:     "/api/v1",
			Domain:   "127.0.0.1",
			Secure:   true,
			HttpOnly: true,
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	// Test partial matches in cookie name
	if !cookies.Contains("complex") {
		t.Error("expected Contains to find partial match in cookie name")
	}

	// Test partial matches in cookie value
	if !cookies.Contains("complex-value") {
		t.Error("expected Contains to find partial match in cookie value")
	}

	// Test partial matches in cookie attributes (path, domain, etc.)
	if !cookies.Contains("/api") {
		t.Error("expected Contains to find partial match in cookie path")
	}

	if !cookies.Contains("127.0.0.1") {
		t.Error("expected Contains to find partial match in cookie domain")
	}

	// Test cookie flags
	if !cookies.Contains("secure") {
		t.Error("expected Contains to find secure flag in cookie string")
	}

	if !cookies.Contains("httponly") {
		t.Error("expected Contains to find httponly flag in cookie string")
	}
}

func TestCookiesContainsComplexRegexp(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "jwt-token",
			Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
		})
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "timestamp",
			Value: "1640995200",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	// Test JWT token pattern - based on other tests, Contains() matches against cookie name or value
	// First test if the cookie name exists
	if !cookies.Contains("jwt-token") {
		t.Error("expected jwt-token cookie to be present")
	}

	// Test JWT token value pattern with regex (cookies.Contains() makes everything lowercase)
	jwtPattern, err := regexp.Compile(`eyj.*signature`)
	if err != nil {
		t.Fatalf("failed to compile JWT regexp: %v", err)
	}

	if !cookies.Contains(jwtPattern) {
		t.Error("expected Contains to match JWT token value pattern")
	}

	// Test timestamp pattern (Unix timestamp)
	timestampPattern, err := regexp.Compile(`\d{10}`)
	if err != nil {
		t.Fatalf("failed to compile timestamp regexp: %v", err)
	}

	if !cookies.Contains(timestampPattern) {
		t.Error("expected Contains to match timestamp pattern")
	}

	// Test complex pattern that combines multiple parts
	combinedPattern, err := regexp.Compile(`(jwt-token|1640995200)`)
	if err != nil {
		t.Fatalf("failed to compile combined regexp: %v", err)
	}

	if !cookies.Contains(combinedPattern) {
		t.Error("expected Contains to match combined pattern")
	}
}

func TestCookiesContainsUnsupportedTypes(t *testing.T) {
	t.Parallel()

	handler := func(w ehttp.ResponseWriter, _ *ehttp.Request) {
		ehttp.SetCookie(w, &ehttp.Cookie{
			Name:  "test",
			Value: "value",
		})
		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(ehttp.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Session().Build()
	resp := client.Get(g.String(ts.URL)).Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	cookies := resp.Ok().Cookies

	// Test with unsupported types - should return false
	if cookies.Contains(123) {
		t.Error("expected Contains to return false for int type")
	}

	if cookies.Contains([]string{"test"}) {
		t.Error("expected Contains to return false for slice type")
	}

	if cookies.Contains(map[string]string{"test": "value"}) {
		t.Error("expected Contains to return false for map type")
	}

	if cookies.Contains(true) {
		t.Error("expected Contains to return false for bool type")
	}

	// Test with nil pattern
	if cookies.Contains(nil) {
		t.Error("expected Contains to return false for nil pattern")
	}
}
