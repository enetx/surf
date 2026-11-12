package firefox_test

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox"
	"github.com/enetx/surf/profiles/firefox/desktop"
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
	// Ordinary Firefox 160 fetch does not add cache bypass directives.
	if v := h.Get(header.CACHE_CONTROL).UnwrapOrDefault(); v != "" {
		t.Errorf("POST Cache-Control = %q, want no directive", v)
	}
	if v := h.Get(header.PRAGMA).UnwrapOrDefault(); v != "" {
		t.Errorf("POST Pragma = %q, want no directive", v)
	}
	if v := h.Get(header.PRIORITY).UnwrapOrDefault(); v != "u=4" {
		t.Errorf("POST Priority = %q, want ordinary fetch urgency u=4", v)
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
		version := "160.0"
		if c.os.IsMobile() {
			version = "148.0"
		}
		if !strings.Contains(string(ua.Unwrap()), version) {
			t.Errorf("UserAgent[%v] = %q, expected version %s", c.os, ua.Unwrap(), version)
		}
	}
}

func TestVariantDesktopFields(t *testing.T) {
	t.Parallel()

	if firefox.Desktop.HelloSpec != &firefox.HelloFirefox_160 {
		t.Error("Desktop.HelloSpec must point to HelloFirefox_160")
	}
	if firefox.Desktop.ShuffleExtensions {
		t.Error("Firefox must retain its fixed extension order")
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

	if len(h.Keys()) != 3 {
		t.Errorf("identity fragment has %d fields, want UA, language and encoding only", len(h.Keys()))
	}
	if h.Contains(":authority") || h.Contains(header.ACCEPT) || h.Contains(header.SEC_FETCH_MODE) {
		t.Error("identity fragment must not preselect a request scenario or protocol")
	}
	if got := h.Get(header.ACCEPT_ENCODING).UnwrapOrDefault(); got != "gzip, deflate, br, zstd" {
		t.Errorf("Desktop[Accept-Encoding] = %q", got)
	}
	if got := h.Get(header.ACCEPT_LANGUAGE).UnwrapOrDefault(); got != "en-US,en;q=0.9" {
		t.Errorf("Desktop[Accept-Language] = %q", got)
	}
	ua := h.Get(header.USER_AGENT).UnwrapOrDefault()
	if !strings.Contains(string(ua), "Macintosh") || !strings.Contains(string(ua), "Firefox/160.0") {
		t.Errorf("Desktop[User-Agent] = %q, expected Macintosh + Firefox/160.0", ua)
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

	pattern := regexp.MustCompile(`^----geckoformboundary[0-9a-f]{2,32}$`)
	seen := make(map[string]bool)
	for range 64 {
		b := string(firefox.Boundary())
		if !pattern.MatchString(b) || seen[b] {
			t.Fatalf("invalid or repeated Firefox multipart boundary: %s", b)
		}
		seen[b] = true
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
	if got := headers.Get(header.CACHE_CONTROL).UnwrapOrDefault(); got != "" {
		t.Errorf("Cache-Control after Apply (string path) = %q, want no directive", got)
	}
	if got := headers.Get(header.PRIORITY).UnwrapOrDefault(); got != "u=4" {
		t.Errorf("Priority after Apply (string path) = %q, want u=4", got)
	}
}

func TestDesktopHTTP3FetchHeaders(t *testing.T) {
	t.Parallel()

	h := firefox.Desktop.BuildRequestHeaders(profiles.HeaderContext{
		Request:  &http.Request{Method: http.MethodPost},
		OS:       profiles.Windows,
		Protocol: 3,
	})
	if got := h.Get(header.ACCEPT).Unwrap(); got != "*/*" {
		t.Errorf("fetch Accept = %q, want */*", got)
	}
	if got := h.Get(header.SEC_FETCH_MODE).Unwrap(); got != "cors" {
		t.Errorf("fetch mode = %q, want cors", got)
	}
	if h.Contains(header.TE) || h.Contains(header.SEC_FETCH_USER) || h.Contains(header.UPGRADE_INSECURE_REQUESTS) {
		t.Error("HTTP/3 fetch has unexpected HTTP/1.1-2 or navigation defaults")
	}
}

func TestHeaderApplierOrdinaryFetchMethods(t *testing.T) {
	t.Parallel()

	// Native Firefox 160 fetch captures cover these methods with Priority: u=4
	// and no cache bypass directives. Request scenario is independent of method.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpHandler.cpp#L947
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			h := g.NewMapOrd[string, string]()
			h.Insert(header.SEC_FETCH_MODE, "cors")
			firefox.Desktop.Headers(&h, method)

			if got := h.Get(header.PRIORITY).UnwrapOrDefault(); got != "u=4" {
				t.Errorf("ordinary %s fetch Priority = %q, want u=4", method, got)
			}
			for _, name := range []string{header.PRAGMA, header.CACHE_CONTROL, header.UPGRADE_INSECURE_REQUESTS, header.SEC_FETCH_USER} {
				if got := h.Get(name).UnwrapOrDefault(); got != "" {
					t.Errorf("ordinary %s fetch unexpectedly emits %s: %q", method, name, got)
				}
			}
		})
	}
}

func TestHeaderApplierPreservesApplicationFields(t *testing.T) {
	t.Parallel()

	h := g.NewMapOrd[string, string]()
	h.Insert("AcCePt", "application/json")
	h.Insert(header.SEC_FETCH_MODE, "cors")
	h.Insert(header.PRIORITY, "u=6")
	h.Insert("X-Application", "custom")
	before := h.Clone()

	firefox.Desktop.Headers(&h, http.MethodGet)

	for name, value := range before.Iter() {
		if got := h.Get(name).UnwrapOrDefault(); got != value {
			t.Errorf("application field %s = %q, want %q", name, got, value)
		}
	}
	acceptFields := 0
	for name := range h.Iter().Keys() {
		if strings.EqualFold(name, header.ACCEPT) {
			acceptFields++
		}
	}
	if acceptFields != 1 {
		t.Errorf("case-insensitive Accept fields = %d, want one supplied field", acceptFields)
	}
}

func TestHeaderApplierPreservesSelectedIdentity(t *testing.T) {
	t.Parallel()

	h := firefox.Desktop.BuildHeaders(profiles.MacOS)
	userAgent := h.Get(header.USER_AGENT).Unwrap()
	h.Insert(header.ACCEPT_LANGUAGE, "de-DE,de;q=0.8")
	firefox.Desktop.Headers(h, http.MethodPost)

	if got := h.Get(header.USER_AGENT).UnwrapOrDefault(); got != userAgent {
		t.Errorf("selected Mac identity changed to %q", got)
	}
	if got := h.Get(header.ACCEPT_LANGUAGE).UnwrapOrDefault(); got != "de-DE,de;q=0.8" {
		t.Errorf("application language changed to %q", got)
	}
	if got := h.Get(header.ACCEPT).UnwrapOrDefault(); got != "*/*" {
		t.Errorf("POST fetch Accept = %q, want */*", got)
	}
}

func TestHeaderApplierDefaultDeviceIdentity(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		apply   profiles.HeadersApplier
		marker  string
		version string
	}{
		{"desktop", firefox.Desktop.Headers, "Windows NT", "Firefox/160.0"},
		{"android", firefox.Mobile.Headers, "Android", "Firefox/148.0"},
		{"ios", firefox.IOS.Headers, "iPhone", "FxiOS/148.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := g.NewMapOrd[g.String, g.String]()
			tc.apply(&h, http.MethodGet)
			ua := h.Get(header.USER_AGENT).UnwrapOrDefault().Std()
			if !strings.Contains(ua, tc.marker) || !strings.Contains(ua, tc.version) {
				t.Errorf("default %s identity = %q, want %s and %s", tc.name, ua, tc.marker, tc.version)
			}
		})
	}
}

func TestProtocolHeaderAdapterUsesFetchLayout(t *testing.T) {
	t.Parallel()

	h := http.Header{
		"Sec-Fetch-Mode": {"cors"},
		"Referer":        {"http://example.test/start"},
		"Content-Type":   {"text/plain;charset=UTF-8"},
		"Content-Length": {"5"},
		"Origin":         {"http://example.test"},
	}
	desktop.ProtocolHeaders(h, 1)

	// Independent Firefox 160 fetch bytes place Connection after the complete
	// upload block; navigation's earlier Connection position is a different case.
	want := []string{header.REFERER, header.CONTENT_TYPE, header.CONTENT_LENGTH, header.ORIGIN, header.CONNECTION}
	var got []string
	for _, name := range h[http.HeaderOrderKey] {
		if slices.Contains(want, name) {
			got = append(got, name)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fetch upload field order = %v, want %v", got, want)
	}
	if got := h.Get(header.CONNECTION); got != "keep-alive" {
		t.Errorf("HTTP/1 Connection = %q, want keep-alive", got)
	}
}

func TestProtocolHeaderAdapterPreservesExplicitMetadata(t *testing.T) {
	t.Parallel()

	for _, protocol := range []int{1, 2, 3} {
		h := http.Header{
			http.HeaderOrderKey:  {"x-first", "x-last"},
			http.PHeaderOrderKey: {":path", ":method", ":scheme", ":authority"},
			http.HeaderCaseKey:   {"X-Application"},
			"Connection":         {"close"},
			"te":                 nil,
		}
		before := h.Clone()
		desktop.ProtocolHeaders(h, protocol)
		if !reflect.DeepEqual(h, before) {
			t.Errorf("HTTP/%d protocol adapter changed explicit metadata or suppressed fields: got %v, want %v", protocol, h, before)
		}
	}
}
