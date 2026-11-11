package chrome_test

import (
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome"
	utls "github.com/refraction-networking/utls"
)

func TestHeaders_POST(t *testing.T) {
	t.Run("POST method sets correct headers", func(t *testing.T) {
		headers := g.NewMapOrd[string, string]()
		chrome.DesktopApplier(&headers, http.MethodPost)

		if v := headers.Get(header.ACCEPT); v.Unwrap() != "*/*" {
			t.Errorf("Expected Accept header to be '*/*', got %s", v.Unwrap())
		}

		if headers.Contains(header.CACHE_CONTROL) {
			t.Error("POST must not force Cache-Control: no-cache")
		}

		if v := headers.Get(header.CONTENT_TYPE); v.Unwrap() != "" {
			t.Errorf("Expected Content-Type header to be empty, got %s", v.Unwrap())
		}

		if headers.Contains(header.PRAGMA) {
			t.Error("POST must not force Pragma: no-cache")
		}

		if v := headers.Get(header.PRIORITY); v.Unwrap() != "" {
			t.Errorf("Priority default must wait for protocol selection, got %s", v.Unwrap())
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

		if got := headers.Keys(); !slices.Equal(got, expectedOrder) {
			t.Errorf("POST header order\n got: %v\nwant: %v", got, expectedOrder)
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
		headers.Insert(header.CACHE_CONTROL, "max-age=0")
		headers.Insert(header.PRAGMA, "no-cache")

		chrome.DesktopApplier(&headers, http.MethodPost)

		if v := headers.Get("X-Custom-Header"); v.Unwrap() != "custom-value" {
			t.Errorf("Expected X-Custom-Header to be preserved, got %s", v.Unwrap())
		}

		if v := headers.Get(header.AUTHORIZATION); v.Unwrap() != "Bearer token123" {
			t.Errorf("Expected Authorization header to be preserved, got %s", v.Unwrap())
		}
		if got := headers.Get(header.CACHE_CONTROL).Unwrap(); got != "max-age=0" {
			t.Errorf("explicit Cache-Control = %q, want max-age=0", got)
		}
		if got := headers.Get(header.PRAGMA).Unwrap(); got != "no-cache" {
			t.Errorf("explicit Pragma = %q, want no-cache", got)
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
	t.Run("Android uses the same navigation defaults as desktop", func(t *testing.T) {
		desktop := g.NewMapOrd[string, string]()
		mobile := g.NewMapOrd[string, string]()

		chrome.DesktopApplier(&desktop, http.MethodGet)
		chrome.MobileApplier(&mobile, http.MethodGet)

		dDest := desktop.Get(header.SEC_FETCH_DEST).UnwrapOrDefault()
		mDest := mobile.Get(header.SEC_FETCH_DEST).UnwrapOrDefault()
		if dDest != mDest {
			t.Error("mobile and desktop Sec-Fetch-Dest differ between Android and desktop")
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
	if !strings.Contains(chrome.SecCHUA, `v="157"`) {
		t.Errorf("SecCHUA missing version 157: %s", chrome.SecCHUA)
	}
}

func TestVariantDesktopFields(t *testing.T) {
	t.Parallel()

	if chrome.Desktop.HelloSpec == nil {
		t.Fatal("Desktop.HelloSpec is nil")
	}
	if chrome.Desktop.HelloSpec != &chrome.HelloChrome_157 {
		t.Error("Desktop.HelloSpec must point to HelloChrome_157")
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
	if chrome.Mobile.HelloSpec != &chrome.HelloChrome_157_Mobile {
		t.Error("Mobile.HelloSpec must point to HelloChrome_157_Mobile")
	}
	if chrome.Mobile.HelloSpec == &chrome.HelloChrome_157 {
		t.Error("Mobile.HelloSpec must NOT point to the desktop spec")
	}
	if chrome.Mobile.Boundary == nil {
		t.Error("Mobile.Boundary is nil")
	}
	if chrome.Mobile.BuildHeaders == nil {
		t.Error("Mobile.BuildHeaders is nil")
	}
}

// trustAnchorsExtension returns the TLS Trust Anchor Identifiers extension (0xca34)
// from a hello spec, or nil when the spec does not carry it.
func trustAnchorsExtension(spec *utls.ClientHelloSpec) *utls.TrustAnchorsExtension {
	for _, ext := range spec.Extensions {
		if anchors, ok := ext.(*utls.TrustAnchorsExtension); ok {
			return anchors
		}
	}
	return nil
}

// chromeTrustAnchors is the trust_anchors (0xca34) body of a Google Chrome 156 desktop
// ClientHello. Chrome emits this list in compiled-in root store order and never shuffles it, so
// the bytes have to match exactly — a wrong order is as visible on the wire as a wrong set.
const chromeTrustAnchors = "00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df13" +
	"02130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d" +
	"010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a64" +
	"8c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d6" +
	"79090b04d679090c04d679090d04d679090f"

func TestHelloChrome157TrustAnchors(t *testing.T) {
	t.Parallel()

	for name, spec := range map[string]*utls.ClientHelloSpec{
		"desktop": &chrome.HelloChrome_157,
		"mobile":  &chrome.HelloChrome_157_Mobile,
	} {
		ext := trustAnchorsExtension(spec)
		if ext == nil {
			t.Fatalf("%s: HelloChrome_157 must carry the trust_anchors extension (0xca34)", name)
		}
		if len(ext.TrustAnchorIDs) != 28 {
			t.Errorf("%s: got %d trust anchors, want 28", name, len(ext.TrustAnchorIDs))
		}
		wire := make([]byte, ext.Len())
		if _, err := ext.Read(wire); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		data := wire[4:] // Strip the extension ID and length.
		// TrustAnchorIdentifierList: 2-byte length prefix covering the remaining body.
		if len(data) < 2 || int(data[0])<<8|int(data[1]) != len(data)-2 {
			t.Errorf("%s: trust_anchors body length prefix does not match body (%d bytes)", name, len(data))
		}
		if len(data) != 186 {
			t.Errorf("%s: trust_anchors body is %d bytes, Chrome 156 sends 186", name, len(data))
		}
		if got := hex.EncodeToString(data); got != chromeTrustAnchors {
			t.Errorf("%s: trust_anchors body differs from the Chrome 156 capture\n got: %s\nwant: %s", name, got, chromeTrustAnchors)
		}
	}
}

func TestHelloChrome157SignatureAlgorithmsGREASE(t *testing.T) {
	t.Parallel()

	for _, ext := range chrome.HelloChrome_157.Extensions {
		sigalgs, ok := ext.(*utls.SignatureAlgorithmsExtension)
		if !ok {
			continue
		}
		if len(sigalgs.SupportedSignatureAlgorithms) == 0 || sigalgs.SupportedSignatureAlgorithms[0] != utls.GREASE_PLACEHOLDER {
			t.Fatalf("signature_algorithms must start with a GREASE placeholder, got %v", sigalgs.SupportedSignatureAlgorithms)
		}
		return
	}
	t.Fatal("HelloChrome_157 has no signature_algorithms extension")
}

// uTLS shuffles Chrome's extension order when creating the spec. Pin the set;
// JA wire tests check per-connection shuffling and template immutability.
func TestHelloChrome157ExtensionSet(t *testing.T) {
	t.Parallel()

	want := []string{
		"*tls.UtlsGREASEExtension",
		"*tls.SNIExtension",
		"*tls.ExtendedMasterSecretExtension",
		"*tls.RenegotiationInfoExtension",
		"*tls.SupportedCurvesExtension",
		"*tls.SupportedPointsExtension",
		"*tls.SessionTicketExtension",
		"*tls.ALPNExtension",
		"*tls.StatusRequestExtension",
		"*tls.SignatureAlgorithmsExtension",
		"*tls.SCTExtension",
		"*tls.KeyShareExtension",
		"*tls.PSKKeyExchangeModesExtension",
		"*tls.SupportedVersionsExtension",
		"*tls.UtlsCompressCertExtension",
		"*tls.ApplicationSettingsExtensionNew",
		"*tls.TrustAnchorsExtension",
		"*tls.GREASEEncryptedClientHelloExtension",
		"*tls.UtlsGREASEExtension",
		"*tls.UtlsPreSharedKeyExtension",
	}
	slices.Sort(want)
	got := make([]string, 0, len(chrome.HelloChrome_157.Extensions))
	for _, ext := range chrome.HelloChrome_157.Extensions {
		got = append(got, fmt.Sprintf("%T", ext))
	}
	if got[len(got)-1] != "*tls.UtlsPreSharedKeyExtension" {
		t.Error("pre_shared_key must remain last")
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("HelloChrome_157 extension set changed\n got: %v\nwant: %v", got, want)
	}
}

func TestVariantsShuffleExtensions(t *testing.T) {
	t.Parallel()

	if !chrome.Desktop.ShuffleExtensions {
		t.Error("Desktop must re-shuffle extensions per connection like Chrome")
	}
	if !chrome.Mobile.ShuffleExtensions {
		t.Error("Mobile must re-shuffle extensions per connection like Chrome")
	}
}

func TestBuildHeadersDesktop(t *testing.T) {
	t.Parallel()

	h := chrome.Desktop.BuildHeaders(profiles.Windows)

	checks := map[g.String]g.String{
		":authority":            "",
		":method":               "",
		":path":                 "",
		":scheme":               "",
		header.ACCEPT_ENCODING:  "gzip, deflate, br, zstd",
		header.ACCEPT_LANGUAGE:  "en-US,en;q=0.9",
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
	if headers.Contains(header.CACHE_CONTROL) {
		t.Error("Cache-Control should be absent unless explicitly set")
	}
}
