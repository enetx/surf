package surf_test

import (
	"fmt"
	"net/http"
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
			Domain:   "example.com",
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

	if secureCookie.Domain != "example.com" {
		t.Errorf("expected cookie domain to be example.com, got %s", secureCookie.Domain)
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
