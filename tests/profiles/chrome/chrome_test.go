package chrome_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
)

func TestHeaders_POST(t *testing.T) {
	t.Run("POST method sets correct headers", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()
		chrome.DesktopApplier(&headers, http.MethodPost)

		if v := headers.Get(header.ACCEPT); v.Unwrap() != "*/*" {
			t.Errorf("Expected Accept header to be '*/*', got %s", v.Unwrap())
		}

		if v := headers.Get(header.CACHE_CONTROL); v.Unwrap() != "no-cache" {
			t.Errorf("Expected Cache-Control header to be 'no-cache', got %s", v.Unwrap())
		}

		if v := headers.Get(header.CONTENT_TYPE); v.Unwrap() != "" {
			t.Errorf("Expected Content-Type header to be empty, got %s", v.Unwrap())
		}

		if v := headers.Get(header.PRAGMA); v.Unwrap() != "no-cache" {
			t.Errorf("Expected Pragma header to be 'no-cache', got %s", v.Unwrap())
		}

		if v := headers.Get(header.PRIORITY); v.Unwrap() != "u=1, i" {
			t.Errorf("Expected Priority header to be 'u=1, i', got %s", v.Unwrap())
		}

		if v := headers.Get(header.SEC_FETCH_DEST); v.Unwrap() != "empty" {
			t.Errorf("Expected Sec-Fetch-Dest header to be 'empty', got %s", v.Unwrap())
		}

		if v := headers.Get(header.SEC_FETCH_MODE); v.Unwrap() != "cors" {
			t.Errorf("Expected Sec-Fetch-Mode header to be 'cors', got %s", v.Unwrap())
		}

		if v := headers.Get(header.SEC_FETCH_SITE); v.Unwrap() != "same-origin" {
			t.Errorf("Expected Sec-Fetch-Site header to be 'same-origin', got %s", v.Unwrap())
		}
	})

	t.Run("POST method header order", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()

		headers.Insert(":method", "POST")
		headers.Insert(":authority", "127.0.0.1")
		headers.Insert(":scheme", "https")
		headers.Insert(":path", "/api")
		headers.Insert(header.CONTENT_LENGTH, "100")
		headers.Insert(header.USER_AGENT, "Mozilla/5.0")
		headers.Insert(header.REFERER, "https://127.0.0.1")
		headers.Insert(header.COOKIE, "session=abc")
		headers.Insert(header.ACCEPT_ENCODING, "gzip, deflate")
		headers.Insert(header.ACCEPT_LANGUAGE, "en-US")
		headers.Insert(header.ORIGIN, "https://127.0.0.1")

		chrome.DesktopApplier(&headers, http.MethodPost)

		expectedOrder := []string{
			":method",
			":authority",
			":scheme",
			":path",
			header.CONTENT_LENGTH,
			header.PRAGMA,
			header.CACHE_CONTROL,
			header.USER_AGENT,
			header.CONTENT_TYPE,
			header.ACCEPT,
			header.ORIGIN,
			header.SEC_FETCH_SITE,
			header.SEC_FETCH_MODE,
			header.SEC_FETCH_DEST,
			header.REFERER,
			header.ACCEPT_ENCODING,
			header.ACCEPT_LANGUAGE,
			header.COOKIE,
			header.PRIORITY,
		}

		keys := headers.Keys()

		for i, expected := range expectedOrder {
			if g.Int(i) >= keys.Len() {
				t.Errorf("Missing header at position %d: expected %s", i, expected)
				continue
			}

			if !headers.Contains(expected) {
				continue
			}

			found := slices.Contains(keys, expected)

			if !found {
				t.Errorf("Header %s not found in the ordered map", expected)
			}
		}
	})

	t.Run("POST method doesn't set GET-specific headers", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()
		chrome.DesktopApplier(&headers, http.MethodPost)

		if headers.Contains(header.SEC_FETCH_USER) {
			t.Errorf("Sec-Fetch-User header should not be set for POST requests")
		}

		if headers.Contains(header.UPGRADE_INSECURE_REQUESTS) {
			t.Errorf("Upgrade-Insecure-Requests header should not be set for POST requests")
		}
	})

	t.Run("POST method preserves existing headers", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()

		headers.Insert("X-Custom-Header", "custom-value")
		headers.Insert(header.AUTHORIZATION, "Bearer token123")

		chrome.DesktopApplier(&headers, http.MethodPost)

		if v := headers.Get("X-Custom-Header"); v.Unwrap() != "custom-value" {
			t.Errorf("Expected X-Custom-Header to be preserved, got %s", v.Unwrap())
		}

		if v := headers.Get(header.AUTHORIZATION); v.Unwrap() != "Bearer token123" {
			t.Errorf("Expected Authorization header to be preserved, got %s", v.Unwrap())
		}
	})
}

func TestHeaders_GET(t *testing.T) {
	t.Run("GET sets navigation-mode headers", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()
		chrome.DesktopApplier(&headers, http.MethodGet)

		if v := headers.Get(header.SEC_FETCH_DEST); v.Unwrap() != "document" {
			t.Errorf("expected Sec-Fetch-Dest=document, got %s", v.Unwrap())
		}
		if v := headers.Get(header.SEC_FETCH_MODE); v.Unwrap() != "navigate" {
			t.Errorf("expected Sec-Fetch-Mode=navigate, got %s", v.Unwrap())
		}
		if v := headers.Get(header.SEC_FETCH_USER); v.Unwrap() != "?1" {
			t.Errorf("expected Sec-Fetch-User=?1, got %s", v.Unwrap())
		}
		if v := headers.Get(header.UPGRADE_INSECURE_REQUESTS); v.Unwrap() != "1" {
			t.Errorf("expected Upgrade-Insecure-Requests=1, got %s", v.Unwrap())
		}
	})

	t.Run("GET does not set POST-specific headers", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()
		chrome.DesktopApplier(&headers, http.MethodGet)

		if headers.Contains(header.CACHE_CONTROL) {
			t.Error("Cache-Control should not be set for GET")
		}
		if headers.Contains(header.PRAGMA) {
			t.Error("Pragma should not be set for GET")
		}
	})
}

func TestHeaders_Mobile(t *testing.T) {
	t.Run("mobile=true reaches the mobile branch and produces same placeholder set", func(t *testing.T) {
		desktop := g.NewMapOrd[string, string]()
		mobile := g.NewMapOrd[string, string]()

		chrome.DesktopApplier(&desktop, http.MethodGet)
		chrome.MobileApplier(&mobile, http.MethodGet)

		// На старте mobile-инсёрты — копия desktop. Когда они разойдутся, заменить тело
		// insertMobileHeaders, и этот тест станет негативным гейтом.
		dDest := desktop.Get(header.SEC_FETCH_DEST).UnwrapOrDefault()
		mDest := mobile.Get(header.SEC_FETCH_DEST).UnwrapOrDefault()
		if dDest != mDest {
			t.Error("mobile and desktop Sec-Fetch-Dest diverged unexpectedly at placeholder stage")
		}
	})

	t.Run("mobile branch reuses POST inserts", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()
		chrome.MobileApplier(&headers, http.MethodPost)

		if v := headers.Get(header.ACCEPT); v.Unwrap() != "*/*" {
			t.Errorf("mobile POST Accept = %q, want */*", v.Unwrap())
		}
		if v := headers.Get(header.SEC_FETCH_SITE); v.Unwrap() != "same-origin" {
			t.Errorf("mobile POST Sec-Fetch-Site = %q, want same-origin", v.Unwrap())
		}
	})
}

func TestUserAgentMap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		os     profiles.OSKey
		marker string
	}{
		{profiles.Windows, "Windows NT"},
		{profiles.MacOS, "Macintosh"},
		{profiles.Linux, "Linux"},
		{profiles.Android, "Android"},
		{profiles.IOS, "iPhone"},
	}

	for _, c := range cases {
		ua := chrome.UserAgent.Get(c.os)
		if ua.IsNone() {
			t.Errorf("UserAgent[%v] missing", c.os)
			continue
		}
		if !strings.Contains(string(ua.Unwrap()), c.marker) {
			t.Errorf("UserAgent[%v] = %q, expected to contain %q", c.os, ua.Unwrap(), c.marker)
		}
	}
}

func TestPlatformMap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		os   profiles.OSKey
		want g.String
	}{
		{profiles.Windows, `"Windows"`},
		{profiles.MacOS, `"macOS"`},
		{profiles.Linux, `"Linux"`},
		{profiles.Android, `"Android"`},
		{profiles.IOS, `"iOS"`},
	}

	for _, c := range cases {
		got := chrome.Platform.Get(c.os).UnwrapOrDefault()
		if got != c.want {
			t.Errorf("Platform[%v] = %q, want %q", c.os, got, c.want)
		}
	}
}

func TestSecCHUAFormat(t *testing.T) {
	t.Parallel()

	if !strings.Contains(chrome.SecCHUA, "Google Chrome") {
		t.Errorf("SecCHUA missing Chrome brand: %s", chrome.SecCHUA)
	}
	if !strings.Contains(chrome.SecCHUA, "Chromium") {
		t.Errorf("SecCHUA missing Chromium brand: %s", chrome.SecCHUA)
	}
	if !strings.Contains(chrome.SecCHUA, `v="145"`) {
		t.Errorf("SecCHUA missing version 145: %s", chrome.SecCHUA)
	}
}

func TestVariantDesktopFields(t *testing.T) {
	t.Parallel()

	if chrome.Desktop.HelloSpec == nil {
		t.Fatal("Desktop.HelloSpec is nil")
	}
	if chrome.Desktop.HelloSpec != &chrome.HelloChrome_145 {
		t.Error("Desktop.HelloSpec must point to HelloChrome_145")
	}
	if chrome.Desktop.Boundary == nil {
		t.Error("Desktop.Boundary is nil")
	}
	if chrome.Desktop.ConfigureH2 == nil {
		t.Error("Desktop.ConfigureH2 is nil")
	}
	if chrome.Desktop.ConfigureH3 == nil {
		t.Error("Desktop.ConfigureH3 is nil")
	}
	if chrome.Desktop.BuildHeaders == nil {
		t.Error("Desktop.BuildHeaders is nil")
	}
}

func TestVariantMobileFields(t *testing.T) {
	t.Parallel()

	if chrome.Mobile.HelloSpec == nil {
		t.Fatal("Mobile.HelloSpec is nil")
	}
	if chrome.Mobile.HelloSpec != &chrome.HelloChrome_145_Mobile {
		t.Error("Mobile.HelloSpec must point to HelloChrome_145_Mobile")
	}
	if chrome.Mobile.HelloSpec == &chrome.HelloChrome_145 {
		t.Error("Mobile.HelloSpec must NOT point to the desktop spec")
	}
	if chrome.Mobile.Boundary == nil {
		t.Error("Mobile.Boundary is nil")
	}
	if chrome.Mobile.BuildHeaders == nil {
		t.Error("Mobile.BuildHeaders is nil")
	}
}

func TestBuildHeadersDesktop(t *testing.T) {
	t.Parallel()

	h := chrome.Desktop.BuildHeaders(profiles.Windows)

	checks := map[g.String]g.String{
		":authority":           "",
		":method":              "",
		":path":                "",
		":scheme":              "",
		header.ACCEPT_ENCODING: "gzip, deflate, br, zstd",
		header.ACCEPT_LANGUAGE: "en-US,en;q=0.9",
		header.SEC_CH_UA_MOBILE: "?0",
	}
	for k, want := range checks {
		got := h.Get(k).UnwrapOrDefault()
		if got != want {
			t.Errorf("Desktop[%s] = %q, want %q", k, got, want)
		}
	}

	platform := h.Get(header.SEC_CH_UA_PLATFORM).UnwrapOrDefault()
	if platform != `"Windows"` {
		t.Errorf("Desktop[Sec-Ch-Ua-Platform] = %q, want \"Windows\"", platform)
	}
	ua := h.Get(header.USER_AGENT).UnwrapOrDefault()
	if !strings.Contains(string(ua), "Windows NT") {
		t.Errorf("Desktop[User-Agent] = %q, expected Windows NT", ua)
	}
}

func TestBuildHeadersMobile(t *testing.T) {
	t.Parallel()

	h := chrome.Mobile.BuildHeaders(profiles.Android)

	if got := h.Get(header.SEC_CH_UA_MOBILE).UnwrapOrDefault(); got != "?1" {
		t.Errorf("Mobile[Sec-Ch-Ua-Mobile] = %q, want ?1", got)
	}
	if got := h.Get(header.SEC_CH_UA_PLATFORM).UnwrapOrDefault(); got != `"Android"` {
		t.Errorf("Mobile[Sec-Ch-Ua-Platform] = %q, want \"Android\"", got)
	}
	ua := h.Get(header.USER_AGENT).UnwrapOrDefault()
	if !strings.Contains(string(ua), "Android") || !strings.Contains(string(ua), "Mobile Safari") {
		t.Errorf("Mobile[User-Agent] = %q, expected Android + Mobile Safari", ua)
	}
}

func TestBoundaryFormat(t *testing.T) {
	t.Parallel()

	b := chrome.Boundary()
	if !strings.HasPrefix(string(b), "----WebKitFormBoundary") {
		t.Errorf("Boundary must start with ----WebKitFormBoundary, got: %s", b)
	}
	if len(b) != len("----WebKitFormBoundary")+16 {
		t.Errorf("Boundary length = %d, want %d", len(b), len("----WebKitFormBoundary")+16)
	}
}

func TestApplierIsWired(t *testing.T) {
	t.Parallel()

	if chrome.DesktopApplier == nil || chrome.MobileApplier == nil {
		t.Fatal("chrome.DesktopApplier or chrome.MobileApplier is nil")
	}
	if chrome.Desktop.Headers == nil {
		t.Error("Desktop.Headers must be wired to a non-nil applier")
	}
	if chrome.Mobile.Headers == nil {
		t.Error("Mobile.Headers must be wired to a non-nil applier")
	}
}

func TestApplierAppliesGStringPath(t *testing.T) {
	t.Parallel()

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Insert(":method", "GET")
	headers.Insert(":authority", "example.com")
	headers.Insert(":scheme", "https")
	headers.Insert(":path", "/")

	chrome.DesktopApplier(&headers, http.MethodGet)

	// After Headers runs, navigation-mode inserts should appear.
	if got := headers.Get(header.SEC_FETCH_DEST).UnwrapOrDefault(); got != "document" {
		t.Errorf("Sec-Fetch-Dest after Apply = %q, want document", got)
	}
	if got := headers.Get(header.UPGRADE_INSECURE_REQUESTS).UnwrapOrDefault(); got != "1" {
		t.Errorf("Upgrade-Insecure-Requests after Apply = %q, want 1", got)
	}
}

func TestApplierAppliesStringPath(t *testing.T) {
	t.Parallel()

	headers := g.NewMapOrd[string, string]()
	headers.Insert(":method", "POST")
	headers.Insert(":authority", "example.com")
	headers.Insert(":scheme", "https")
	headers.Insert(":path", "/api")

	chrome.DesktopApplier(&headers, http.MethodPost)

	if got := headers.Get(header.ACCEPT).Unwrap(); got != "*/*" {
		t.Errorf("Accept after Apply (string path) = %q, want */*", got)
	}
	if got := headers.Get(header.CACHE_CONTROL).Unwrap(); got != "no-cache" {
		t.Errorf("Cache-Control after Apply (string path) = %q, want no-cache", got)
	}
}
