package firefox_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox"
)

func TestHeaders_GET(t *testing.T) {
	t.Parallel()

	h := g.NewMapOrd[string, string]()
	firefox.DesktopApplier(&h, http.MethodGet)

	if v := h.Get(header.ACCEPT); v.Unwrap() != "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" {
		t.Errorf("GET Accept = %q", v.Unwrap())
	}
	if v := h.Get(header.SEC_FETCH_DEST); v.Unwrap() != "document" {
		t.Errorf("GET Sec-Fetch-Dest = %q", v.Unwrap())
	}
	if v := h.Get(header.UPGRADE_INSECURE_REQUESTS); v.Unwrap() != "1" {
		t.Errorf("GET Upgrade-Insecure-Requests = %q", v.Unwrap())
	}
	if h.Contains(header.CACHE_CONTROL) {
		t.Error("Cache-Control should not be set for GET")
	}
}

func TestHeaders_POST(t *testing.T) {
	t.Parallel()

	h := g.NewMapOrd[string, string]()
	firefox.DesktopApplier(&h, http.MethodPost)

	if v := h.Get(header.ACCEPT); v.Unwrap() != "*/*" {
		t.Errorf("POST Accept = %q, want */*", v.Unwrap())
	}
	if v := h.Get(header.CACHE_CONTROL); v.Unwrap() != "no-cache" {
		t.Errorf("POST Cache-Control = %q", v.Unwrap())
	}
	if v := h.Get(header.PRAGMA); v.Unwrap() != "no-cache" {
		t.Errorf("POST Pragma = %q", v.Unwrap())
	}
	if h.Contains(header.SEC_FETCH_USER) {
		t.Error("Sec-Fetch-User should not be set for POST")
	}
}

func TestHeaders_Mobile(t *testing.T) {
	t.Parallel()

	desktop := g.NewMapOrd[string, string]()
	mobile := g.NewMapOrd[string, string]()

	firefox.DesktopApplier(&desktop, http.MethodGet)
	firefox.MobileApplier(&mobile, http.MethodGet)

	dDest := desktop.Get(header.SEC_FETCH_DEST).UnwrapOrDefault()
	mDest := mobile.Get(header.SEC_FETCH_DEST).UnwrapOrDefault()
	if dDest != mDest {
		t.Error("mobile and desktop Sec-Fetch-Dest diverged unexpectedly at placeholder stage")
	}
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
		{profiles.IOS, "FxiOS"},
	}

	for _, c := range cases {
		ua := firefox.UserAgent.Get(c.os)
		if ua.IsNone() {
			t.Errorf("UserAgent[%v] missing", c.os)
			continue
		}
		if !strings.Contains(string(ua.Unwrap()), c.marker) {
			t.Errorf("UserAgent[%v] = %q, expected to contain %q", c.os, ua.Unwrap(), c.marker)
		}
		if !strings.Contains(string(ua.Unwrap()), "148") {
			t.Errorf("UserAgent[%v] = %q, expected version 148", c.os, ua.Unwrap())
		}
	}
}

func TestVariantDesktopFields(t *testing.T) {
	t.Parallel()

	if firefox.Desktop.HelloSpec != nil {
		t.Error("Desktop.HelloSpec should be nil (Firefox uses HelloID)")
	}
	if firefox.Desktop.HelloID != firefox.HelloFirefox_148 {
		t.Error("Desktop.HelloID must equal HelloFirefox_148")
	}
	if firefox.Desktop.Boundary == nil {
		t.Error("Desktop.Boundary is nil")
	}
	if firefox.Desktop.ConfigureH2 == nil {
		t.Error("Desktop.ConfigureH2 is nil")
	}
	if firefox.Desktop.ConfigureH3 == nil {
		t.Error("Desktop.ConfigureH3 is nil")
	}
	if firefox.Desktop.BuildHeaders == nil {
		t.Error("Desktop.BuildHeaders is nil")
	}
}

func TestVariantMobileFields(t *testing.T) {
	t.Parallel()

	if firefox.Mobile.HelloID != firefox.HelloFirefox_148_Mobile {
		t.Error("Mobile.HelloID must equal HelloFirefox_148_Mobile")
	}
	if firefox.Mobile.Boundary == nil {
		t.Error("Mobile.Boundary is nil")
	}
	if firefox.Mobile.BuildHeaders == nil {
		t.Error("Mobile.BuildHeaders is nil")
	}
}

func TestBuildHeadersDesktop(t *testing.T) {
	t.Parallel()

	h := firefox.Desktop.BuildHeaders(profiles.MacOS)

	if got := h.Get(":authority").UnwrapOrDefault(); got != "" {
		t.Errorf("Desktop[:authority] = %q, want empty", got)
	}
	if got := h.Get(header.ACCEPT_ENCODING).UnwrapOrDefault(); got != "gzip, deflate, br, zstd" {
		t.Errorf("Desktop[Accept-Encoding] = %q", got)
	}
	if got := h.Get(header.ACCEPT_LANGUAGE).UnwrapOrDefault(); got != "en-US,en;q=0.5" {
		t.Errorf("Desktop[Accept-Language] = %q", got)
	}
	ua := h.Get(header.USER_AGENT).UnwrapOrDefault()
	if !strings.Contains(string(ua), "Macintosh") || !strings.Contains(string(ua), "Firefox/148.0") {
		t.Errorf("Desktop[User-Agent] = %q, expected Macintosh + Firefox/148.0", ua)
	}
	// Firefox does not emit UA Client Hints.
	if h.Contains(header.SEC_CH_UA) {
		t.Error("Firefox Desktop must not emit Sec-Ch-Ua")
	}
	if h.Contains(header.SEC_CH_UA_MOBILE) {
		t.Error("Firefox Desktop must not emit Sec-Ch-Ua-Mobile")
	}
	if h.Contains(header.SEC_CH_UA_PLATFORM) {
		t.Error("Firefox Desktop must not emit Sec-Ch-Ua-Platform")
	}
}

func TestBuildHeadersMobile(t *testing.T) {
	t.Parallel()

	h := firefox.Mobile.BuildHeaders(profiles.IOS)

	ua := h.Get(header.USER_AGENT).UnwrapOrDefault()
	if !strings.Contains(string(ua), "FxiOS") || !strings.Contains(string(ua), "Mobile/15E148") {
		t.Errorf("Mobile[User-Agent] = %q, expected FxiOS + Mobile/15E148", ua)
	}
	if h.Contains(header.SEC_CH_UA_MOBILE) {
		t.Error("Firefox Mobile must not emit Sec-Ch-Ua-Mobile")
	}
}

func TestBoundaryFormat(t *testing.T) {
	t.Parallel()

	b := firefox.Boundary()
	if !strings.HasPrefix(string(b), "---------------------------") {
		t.Errorf("Boundary must start with 27 dashes, got: %s", b)
	}
}

func TestApplierIsWired(t *testing.T) {
	t.Parallel()

	if firefox.DesktopApplier == nil || firefox.MobileApplier == nil {
		t.Fatal("firefox.DesktopApplier or firefox.MobileApplier is nil")
	}
	if firefox.Desktop.Headers == nil {
		t.Error("Desktop.Headers must be wired to a non-nil applier")
	}
	if firefox.Mobile.Headers == nil {
		t.Error("Mobile.Headers must be wired to a non-nil applier")
	}
}

func TestApplierAppliesGStringPath(t *testing.T) {
	t.Parallel()

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Insert(":method", "GET")

	firefox.DesktopApplier(&headers, http.MethodGet)

	if got := headers.Get(header.SEC_FETCH_DEST).UnwrapOrDefault(); got != "document" {
		t.Errorf("Sec-Fetch-Dest after Apply = %q, want document", got)
	}
}

func TestApplierAppliesStringPath(t *testing.T) {
	t.Parallel()

	headers := g.NewMapOrd[string, string]()
	headers.Insert(":method", "POST")

	firefox.DesktopApplier(&headers, http.MethodPost)

	if got := headers.Get(header.ACCEPT).Unwrap(); got != "*/*" {
		t.Errorf("Accept after Apply (string path) = %q, want */*", got)
	}
	if got := headers.Get(header.CACHE_CONTROL).Unwrap(); got != "no-cache" {
		t.Errorf("Cache-Control after Apply (string path) = %q, want no-cache", got)
	}
}
