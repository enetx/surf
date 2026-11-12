package common

import (
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/internal/origin"
	"github.com/enetx/surf/profiles"
)

// SecCHUA is Chrome 158's Client Hints brand list for desktop and Android.
// Chromium supplies the protocol reference; the advertised browser identity
// includes the Google Chrome brand. iOS does not send these Client Hints.
// https://github.com/chromium/chromium/blob/158.0.8127.18/components/embedder_support/user_agent_utils.cc
const SecCHUA = `"Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"`

// UserAgent contains Chrome 158 desktop/Android and iOS navigation identities.
// The iOS app build follows the official release; OS fields retain the verified
// device identity and its WebKit transport shape.
// All variants read the values for their operating system.
var UserAgent = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
	profiles.MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
	profiles.Linux:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
	profiles.Android: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Mobile Safari/537.36",
	profiles.IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/158.0.8127.32 Mobile/15E148 Safari/604.1",
}

// Platform maps every supported impersonated OS to its sec-ch-ua-platform header value.
var Platform = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: `"Windows"`,
	profiles.MacOS:   `"macOS"`,
	profiles.Linux:   `"Linux"`,
	profiles.Android: `"Android"`,
	profiles.IOS:     `"iOS"`,
}

const (
	acceptEncoding   = "gzip, deflate, br, zstd"
	acceptLanguage   = "en-US,en;q=0.9"
	navigationAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)

// Headers applies the desktop HTTP/2 header declaration to an ordered map.
// Existing values win. BuildRequestHeaders accepts full protocol/body context.
var Headers = profiles.NewRequestHeadersApplier(BuildRequestHeaders)

// MobileHeaders applies the Android HTTP/2 declaration to an ordered map.
// Existing values win. BuildRequestHeaders accepts full protocol/body context.
var MobileHeaders = profiles.NewRequestHeadersApplier(func(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	c.OS = profiles.Android
	return BuildRequestHeaders(c)
})

// IOSHeaders applies the iOS HTTP/2 declaration to an ordered map.
// Existing values win. BuildIOSRequestHeaders accepts full request context.
var IOSHeaders = profiles.NewRequestHeadersApplier(func(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	c.OS = profiles.IOS
	return BuildIOSRequestHeaders(c)
})

// BuildHeaders returns Chrome's device identity and optional header positions.
// BuildRequestHeaders adds the defaults and ordering for a particular request.
func BuildHeaders(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	h.Insert(":authority", "")
	h.Insert(":method", "")
	h.Insert(":path", "")
	h.Insert(":scheme", "")
	h.Insert(header.ACCEPT_ENCODING, acceptEncoding)
	h.Insert(header.ACCEPT_LANGUAGE, acceptLanguage)
	h.Insert(header.AUTHORIZATION, "")
	h.Insert(header.COOKIE, "")
	h.Insert(header.ORIGIN, "")
	h.Insert(header.REFERER, "")
	h.Insert(header.SEC_CH_UA, SecCHUA)
	h.Insert(header.SEC_CH_UA_MOBILE, os.Mobile())
	h.Insert(header.SEC_CH_UA_PLATFORM, Platform.Get(os).UnwrapOrDefault())
	h.Insert(header.USER_AGENT, UserAgent.Get(os).UnwrapOrDefault())

	return &h
}

// BuildRequestHeaders returns a fresh ordered Chrome desktop or Android preset.
// Explicit Fetch Metadata selects navigation or fetch independently of method.
// Streaming bodies use the same header declaration and are never read here.
func BuildRequestHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	if c.Navigation() {
		return NavigationHeaders(c)
	}

	return FetchHeaders(c)
}

// HeaderPriority follows Chromium's HTTP/2 document and ordinary fetch weights.
// It uses the same request scenario as the header factory, including context
// when Fetch Metadata is absent. The Priority header remains independent.
// Weight is encoded as one less than Chromium's 256/220 stream weights.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/spdy/spdy_session.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/spdy/http2_priority_dependencies.cc
// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/http2/core/spdy_protocol.cc
func HeaderPriority(info http2.PriorityRequest) http2.PriorityParam {
	req := &http.Request{Method: info.Method, URL: info.URL, Header: http.Header(info.Header)}
	if info.Context != nil {
		req = req.WithContext(info.Context)
	}

	weight := uint8(219)
	if (profiles.HeaderContext{Request: req, Protocol: 2}).Navigation() {
		weight = 255
	}

	return http2.PriorityParam{Exclusive: true, Weight: weight}
}

// NavigationHeaders declares Chrome's document-request defaults in wire order.
// A Critical-CH restart appends the rebuilt hint block after Accept; a warm
// navigation restores the block before Upgrade-Insecure-Requests. Redirected
// navigations rebuild the hint block after Fetch Metadata instead.
// https://github.com/chromium/chromium/blob/158.0.8127.18/content/browser/client_hints/client_hints.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/content/browser/client_hints/critical_client_hints_throttle.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/content/browser/renderer_host/navigation_request.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_network_transaction.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/core/loader/form_submission.cc
func NavigationHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	h := pseudoHeaders(c.Protocol)
	h.Insert(header.HOST, "")

	if c.Protocol == 1 {
		h.Insert(header.CONNECTION, connectionValue(c))
	}

	h.Insert(header.CONTENT_LENGTH, "")
	h.Insert(header.PRAGMA, "")

	cacheControl := g.String("")
	if c.Request != nil && c.Request.Method == http.MethodPost {
		// Ordinary POST navigation sets LOAD_VALIDATE_CACHE. Its network
		// transaction emits max-age=0 before the navigation's extra headers.
		// Fetch POST follows the renderer declaration instead.
		cacheControl = "max-age=0"
	}

	h.Insert(header.CACHE_CONTROL, cacheControl)

	appendHints := func() {
		hints := NavigationClientHintHeaders(c)
		hints.Iter().ForEach(func(name, value g.String) { h.Insert(name, value) })
	}

	redirected := c.Redirect || c.Request != nil && c.Request.Response != nil

	if !c.CriticalCH && !redirected {
		appendHints()
	}

	h.Insert(header.AUTHORIZATION, "")
	h.Insert(header.UPGRADE_INSECURE_REQUESTS, "1")
	h.Insert(header.CONTENT_TYPE, "")
	h.Insert(header.USER_AGENT, UserAgent.Get(c.OS).UnwrapOrDefault())
	h.Insert(header.ORIGIN, "")
	h.Insert(header.ACCEPT, navigationAccept)

	if c.CriticalCH {
		appendHints()
	}

	h.Insert(header.SEC_FETCH_SITE, trustworthyValue(c, "none"))
	h.Insert(header.SEC_FETCH_MODE, trustworthyValue(c, "navigate"))
	h.Insert(header.SEC_FETCH_USER, trustworthyValue(c, "?1"))
	h.Insert(header.SEC_FETCH_DEST, trustworthyValue(c, "document"))

	if redirected && !c.CriticalCH {
		// NavigationRequest removes the preceding request's client hints and
		// appends the regenerated block to its existing extra headers.
		appendHints()
	}

	h.Insert(header.REFERER, "")
	h.Insert(header.ACCEPT_ENCODING, requestAcceptEncoding(c))
	h.Insert(header.ACCEPT_LANGUAGE, acceptLanguage)
	h.Insert(header.COOKIE, "")

	if c.Protocol >= 2 {
		h.Insert(header.PRIORITY, "u=0, i")
	}

	return h
}

// FetchHeaders declares Chrome's renderer-request defaults in wire order.
// The renderer block uses Blink's hash-table iteration for the fields actually
// present, rather than one fixed order for every Client Hints subset.
// https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/core/loader/frame_fetch_context.cc
func FetchHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	h := pseudoHeaders(c.Protocol)
	h.Insert(header.HOST, "")

	if c.Protocol == 1 {
		h.Insert(header.CONNECTION, connectionValue(c))
	}

	if c.HasBody() || c.Request != nil && (c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut) {
		// HttpNetworkTransaction always frames an upload, including an explicit
		// empty string. Without an upload only POST and PUT synthesize CL: 0.
		// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_network_transaction.cc
		h.Insert(header.CONTENT_LENGTH, "")
	}

	h.Insert(header.PRAGMA, "")
	h.Insert(header.CACHE_CONTROL, "")

	renderer := RendererHeaders(c)
	renderer.Iter().ForEach(func(name, value g.String) { h.Insert(name, value) })

	h.Insert(header.AUTHORIZATION, "")
	h.Insert(header.ACCEPT, "*/*")
	h.Insert(header.ORIGIN, "")
	h.Insert(header.SEC_FETCH_SITE, trustworthyValue(c, "same-origin"))
	h.Insert(header.SEC_FETCH_MODE, trustworthyValue(c, "cors"))
	h.Insert(header.SEC_FETCH_DEST, trustworthyValue(c, "empty"))
	h.Insert(header.REFERER, "")
	h.Insert(header.ACCEPT_ENCODING, requestAcceptEncoding(c))
	h.Insert(header.ACCEPT_LANGUAGE, acceptLanguage)
	h.Insert(header.COOKIE, "")

	if c.Protocol >= 2 {
		h.Insert(header.PRIORITY, "u=1, i")
	}

	return h
}

func pseudoHeaders(major int) g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	if major == 2 || major == 3 {
		h.Insert(":method", "")
		h.Insert(":authority", "")
		h.Insert(":scheme", "")
		h.Insert(":path", "")
	}
	return h
}

func connectionValue(c profiles.HeaderContext) g.String {
	if c.Request != nil && c.Request.Close {
		return "close"
	}

	return "keep-alive"
}

// A context without a URL is a reusable declaration, not an origin decision.
// Actual requests always use their destination URL, without DNS substitutions.
func requestIsTrustworthy(c profiles.HeaderContext) bool {
	return c.Request == nil || c.Request.URL == nil || origin.TrustworthyHTTP(c.Request.URL)
}

// Chromium restricts Fetch Metadata and Client Hints to trustworthy targets.
// Empty slots keep explicit application values available to the final layout.
// https://github.com/chromium/chromium/blob/158.0.8127.18/services/network/sec_header_helpers.cc
func trustworthyValue(c profiles.HeaderContext, value g.String) g.String {
	if !requestIsTrustworthy(c) {
		return ""
	}
	return value
}

// Advanced decoders are advertised only for cryptographic or localhost URLs.
// For ordinary HTTP(S) requests these match the default trustworthy origins.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_request_headers.cc
func requestAcceptEncoding(c profiles.HeaderContext) g.String {
	if !requestIsTrustworthy(c) {
		return "gzip, deflate"
	}
	return acceptEncoding
}

func requestHeader(c profiles.HeaderContext, name string) (g.String, bool) {
	if c.Request != nil {
		for key, values := range c.Request.Header {
			if strings.EqualFold(key, name) {
				if len(values) == 0 {
					return "", true
				}

				return g.String(values[0]), true
			}
		}
	}

	return "", false
}

// uaHeader supplies only Chromium's low-entropy defaults. A high-entropy field
// enters a preset only after negotiation or an explicit application header.
func uaHeader(c profiles.HeaderContext, name string) (g.String, bool) {
	if value, present := requestHeader(c, name); present {
		return value, true
	}

	switch name {
	case header.SEC_CH_UA:
		return trustworthyValue(c, SecCHUA), true
	case header.SEC_CH_UA_MOBILE:
		return trustworthyValue(c, c.OS.Mobile()), true
	case header.SEC_CH_UA_PLATFORM:
		return trustworthyValue(c, Platform.Get(c.OS).UnwrapOrDefault()), true
	case header.USER_AGENT:
		return UserAgent.Get(c.OS).UnwrapOrDefault(), true
	default:
		return "", false
	}
}

// BuildIOSHeaders constructs the iOS request header set.
func BuildIOSHeaders(_ profiles.OSKey) *g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	h.Insert(":method", "")
	h.Insert(":scheme", "")
	h.Insert(":authority", "")
	h.Insert(":path", "")
	h.Insert(header.USER_AGENT, UserAgent.Get(profiles.IOS).UnwrapOrDefault())
	h.Insert(header.ACCEPT_ENCODING, acceptEncoding)
	h.Insert(header.ACCEPT_LANGUAGE, acceptLanguage)
	h.Insert(header.AUTHORIZATION, "")
	h.Insert(header.COOKIE, "")
	h.Insert(header.ORIGIN, "")
	h.Insert(header.REFERER, "")

	return &h
}

// BuildIOSRequestHeaders returns the retained iOS WebKit header declaration.
// It selects navigation or fetch from request metadata and never enables the
// desktop/Android Client Hints machinery for an iOS identity.
func BuildIOSRequestHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	if c.Navigation() {
		return IOSNavigationHeaders(c)
	}

	return IOSFetchHeaders(c)
}

// IOSNavigationHeaders returns fresh iOS document-request defaults in their
// retained WebKit order. Pseudo-header slots are kept for the late compositor.
func IOSNavigationHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return iosRequestHeaders(c, true)
}

// IOSFetchHeaders returns fresh iOS renderer-request defaults in their retained
// WebKit order. Streaming bodies share the declaration and are never read here.
func IOSFetchHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return iosRequestHeaders(c, false)
}

func iosRequestHeaders(c profiles.HeaderContext, navigation bool) g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	h.Insert(":method", "")
	h.Insert(":scheme", "")
	h.Insert(":authority", "")
	h.Insert(":path", "")

	if navigation {
		h.Insert(header.SEC_FETCH_DEST, "document")
		h.Insert(header.USER_AGENT, UserAgent.Get(profiles.IOS).UnwrapOrDefault())
		h.Insert(header.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		h.Insert(header.SEC_FETCH_SITE, "none")
		h.Insert(header.SEC_FETCH_MODE, "navigate")
	} else {
		h.Insert(header.SEC_FETCH_DEST, "empty")
		h.Insert(header.USER_AGENT, UserAgent.Get(profiles.IOS).UnwrapOrDefault())
		h.Insert(header.ACCEPT, "*/*")
		h.Insert(header.SEC_FETCH_SITE, "same-origin")
		h.Insert(header.SEC_FETCH_MODE, "cors")
	}

	h.Insert(header.ACCEPT_LANGUAGE, acceptLanguage)

	priority := g.String("")
	if c.Protocol != 0 {
		priority = "u=1, i"
		if navigation {
			priority = "u=0, i"
		}
	}

	h.Insert(header.PRIORITY, priority)
	h.Insert(header.ACCEPT_ENCODING, acceptEncoding)
	h.Insert(header.SEC_FETCH_USER, "")
	h.Insert(header.REFERER, "")
	h.Insert(header.COOKIE, "")
	h.Insert(header.CONTENT_TYPE, "")
	h.Insert(header.CONTENT_LENGTH, "")
	h.Insert(header.ORIGIN, "")
	h.Insert(header.AUTHORIZATION, "")

	return h
}

// ClientHints describes the available Chrome 158 UA metadata. Desktop identities
// default to 64-bit x86; applications can select a different architecture and
// target OS version through Builder.ClientHints. Android follows Chromium's
// empty architecture/bitness fields. Device/viewport metrics need application data.
// https://github.com/chromium/chromium/blob/158.0.8127.18/components/embedder_support/user_agent_utils.cc
func ClientHints(os profiles.OSKey) g.MapOrd[string, string] {
	h := g.NewMapOrd[string, string]()
	h.Insert(header.SEC_CH_UA, SecCHUA)
	h.Insert(header.SEC_CH_UA_MOBILE, os.Mobile().Std())
	h.Insert(header.SEC_CH_UA_PLATFORM, Platform.Get(os).UnwrapOrDefault().Std())
	h.Insert("sec-ch-ua-full-version", `"158.0.8127.18"`)
	h.Insert("sec-ch-ua-full-version-list",
		`"Chromium";v="158.0.8127.18", "Not.A/Brand";v="24.0.0.0", "Google Chrome";v="158.0.8127.18"`)
	h.Insert("sec-ch-ua-model", `""`)
	h.Insert("sec-ch-ua-wow64", "?0")

	if os == profiles.Android {
		h.Insert("sec-ch-ua-arch", `""`)
		h.Insert("sec-ch-ua-bitness", `""`)
		h.Insert("sec-ch-ua-platform-version", `"10.0.0"`)
		h.Insert("sec-ch-ua-form-factors", `"Mobile"`)
	} else {
		h.Insert("sec-ch-ua-arch", `"x86"`)
		h.Insert("sec-ch-ua-bitness", `"64"`)
		h.Insert("sec-ch-ua-form-factors", `"Desktop"`)

		switch os {
		case profiles.Windows:
			// Explicit Windows 11 identity; this is not inferred from the Go host.
			h.Insert("sec-ch-ua-platform-version", `"19.0.0"`)
		case profiles.MacOS:
			h.Insert("sec-ch-ua-platform-version", `"27.0.1"`)
		default:
			// Chromium intentionally leaves Linux platform_version empty.
			h.Insert("sec-ch-ua-platform-version", `""`)
		}
	}

	return h
}

var uaHintOrder = []string{
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-full-version",
	"sec-ch-ua-arch",
	"sec-ch-ua-platform",
	"sec-ch-ua-platform-version",
	"sec-ch-ua-model",
	"sec-ch-ua-bitness",
	"sec-ch-ua-wow64",
	"sec-ch-ua-full-version-list",
	"sec-ch-ua-form-factors",
}

// NavigationClientHintHeaders returns the hint block in Chromium's navigation
// insertion order: available device/viewport/network metrics, UA metadata,
// preference hints, then Save-Data. Only the three low-entropy UA defaults are
// supplied automatically; every other value must already exist on the request.
// The returned map is fresh and the request is never modified.
// https://github.com/chromium/chromium/blob/158.0.8127.18/content/browser/client_hints/client_hints.cc
func NavigationClientHintHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	for _, name := range []string{
		"device-memory", "sec-ch-device-memory",
		"dpr", "sec-ch-dpr",
		"viewport-width", "sec-ch-viewport-width", "sec-ch-viewport-height",
		"rtt", "downlink", "ect",
	} {
		if value, present := requestHeader(c, name); present {
			h.Insert(g.String(name), value)
		}
	}

	for _, name := range uaHintOrder {
		if value, present := uaHeader(c, name); present {
			h.Insert(g.String(name), value)
		}
	}

	for _, name := range []string{
		"sec-ch-prefers-color-scheme", "sec-ch-prefers-reduced-motion",
		"sec-ch-prefers-reduced-transparency", "save-data",
	} {
		if value, present := requestHeader(c, name); present {
			h.Insert(g.String(name), value)
		}
	}

	return h
}

// Renderer requests copy an initial Content-Type before adding Client Hints;
// PrepareRequest then adds User-Agent. The network service appends Accept and
// Fetch Metadata after Blink's HTTPHeaderMap has been serialized. The supported
// fields use their source insertion order and 24-bit case-folded hashes, so
// collisions and rehashing follow the actually present subset.
// https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/core/fetch/fetch_manager.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/core/loader/frame_fetch_context.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/platform/loader/fetch/resource_request_utils.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/platform/network/http_header_map.h
// https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/platform/wtf/text/case_folding_hash.h
// https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/platform/wtf/hash_table.h
var rendererFields = []struct {
	name string
	hash uint32
}{
	{header.CONTENT_TYPE, 0x7cd99b},
	{"device-memory", 0x68a8c9},
	{"sec-ch-device-memory", 0x7e3fad},
	{"rtt", 0x61c53d},
	{"downlink", 0x2ff49f},
	{"ect", 0xd28c26},
	{header.SEC_CH_UA, 0x33f009},
	{header.SEC_CH_UA_MOBILE, 0x9b488d},
	{header.SEC_CH_UA_ARCH, 0x16c3d3},
	{header.SEC_CH_UA_PLATFORM, 0xffbec3},
	{header.SEC_CH_UA_PLATFORM_VERSION, 0x6ae0bf},
	{header.SEC_CH_UA_MODEL, 0xf5d4cc},
	{header.SEC_CH_UA_FULL_VERSION, 0xeb1718},
	{header.SEC_CH_UA_FULL_VERSION_LIST, 0x0d6182},
	{header.SEC_CH_UA_BITNESS, 0xc51909},
	{header.SEC_CH_UA_WOW64, 0x03b40c},
	{header.SEC_CH_UA_FORM_FACTORS, 0xb4818e},
	{"save-data", 0xf01174},
	{"sec-ch-prefers-reduced-transparency", 0x2d8c14},
	{"sec-ch-prefers-reduced-motion", 0xfd9a72},
	{"sec-ch-prefers-color-scheme", 0xb33a38},
	{"dpr", 0x5b7e34},
	{"sec-ch-dpr", 0x69834a},
	{"viewport-width", 0xc23a03},
	{"sec-ch-viewport-width", 0x48e15b},
	{"sec-ch-viewport-height", 0xb83163},
	{"width", 0x50e386},
	{"sec-ch-width", 0x0f1737},
	{header.USER_AGENT, 0xc21178},
}

// RendererHeaders returns Chrome's present Client Hints, User-Agent and
// Content-Type in Blink's renderer-map iteration order. Low-entropy UA hints and
// User-Agent use the selected device's defaults; other values must already be in
// the request. No viewport, resource width, preferences or network state is inferred.
// Neither the request nor its body is changed or read.
// https://github.com/chromium/chromium/blob/158.0.8127.18/third_party/blink/renderer/core/loader/frame_fetch_context.cc
func RendererHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	fields := make(http.Header)
	for _, entry := range rendererFields {
		if value, present := uaHeader(c, entry.name); present {
			// Disabled defaults are ordering slots, not fields in Blink's map.
			// Explicit empty fields still participate in the renderer layout.
			if value == "" {
				if _, explicit := requestHeader(c, entry.name); !explicit {
					continue
				}
			}
			fields.Set(entry.name, value.Std())
		}
	}

	h := g.NewMapOrd[g.String, g.String]()
	for _, name := range rendererHeaderNames(fields) {
		h.Insert(g.String(name), g.String(fields.Get(name)))
	}

	return h
}

// HeaderCase returns the present Client Hints names that retain lowercase
// spelling on HTTP/1. Other HTTP versions always use lowercase field names.
// The returned slice is fresh and the request is never modified.
// https://github.com/chromium/chromium/blob/158.0.8127.18/services/network/public/cpp/client_hints.cc
func HeaderCase(c profiles.HeaderContext) []string {
	if c.Protocol != 1 {
		return nil
	}

	hints := NavigationClientHintHeaders(c)

	var names []string
	for _, name := range hints.Keys() {
		if _, present := requestHeader(c, name.Std()); present {
			names = append(names, name.Std())
		}
	}

	// Resource widths are renderer hints rather than navigation hints.
	for _, name := range []string{"width", "sec-ch-width"} {
		if _, present := requestHeader(c, name); present {
			names = append(names, name)
		}
	}

	return names
}

// RequestHeaders applies the request declaration for the selected protocol.
// Missing values and metadata come from BuildRequestHeaders; explicit values,
// ordering and casing retain ownership. It never reads or replaces the body.
func RequestHeaders(req *http.Request, major int) {
	if req == nil {
		return
	}

	if req.Header == nil {
		req.Header = make(http.Header)
	}

	c := profiles.HeaderContext{Request: req, Protocol: major}
	preset := BuildRequestHeaders(c)
	preset.Iter().ForEach(func(name, value g.String) {
		if !strings.HasPrefix(name.Std(), ":") && value != "" {
			if _, present := requestHeader(c, name.Std()); !present {
				req.Header.Set(name.Std(), value.Std())
			}
		}
	})

	if _, explicit := req.Header[http.HeaderOrderKey]; !explicit {
		req.Header[http.HeaderOrderKey] = headerPositions(preset, false)
	}

	if major == 2 || major == 3 {
		if _, explicit := req.Header[http.PHeaderOrderKey]; !explicit {
			req.Header[http.PHeaderOrderKey] = headerPositions(preset, true)
		}
	}

	if major == 1 {
		if _, explicit := req.Header[http.HeaderCaseKey]; !explicit {
			req.Header[http.HeaderCaseKey] = HeaderCase(c)
		}
	}
}

func headerPositions(h g.MapOrd[g.String, g.String], pseudo bool) []string {
	var names []string
	for _, name := range h.Keys() {
		if strings.HasPrefix(name.Std(), ":") == pseudo {
			names = append(names, name.Std())
		}
	}

	return names
}

// ClientHintsOrder rebuilds ordering from the request declaration after hint
// negotiation. The bool identifies a Critical-CH restart. Callers that supply an
// explicit order retain ownership by skipping this callback.
func ClientHintsOrder(req *http.Request, restarted bool) {
	if req == nil {
		return
	}

	if req.Header == nil {
		req.Header = make(http.Header)
	}

	major := req.ProtoMajor
	if major == 0 {
		major = 2
	}

	c := profiles.HeaderContext{Request: req, Protocol: major, CriticalCH: restarted}
	req.Header[http.HeaderOrderKey] = headerPositions(BuildRequestHeaders(c), false)

	if major == 1 {
		if _, explicit := req.Header[http.HeaderCaseKey]; !explicit {
			req.Header[http.HeaderCaseKey] = HeaderCase(c)
		}
	}
}
