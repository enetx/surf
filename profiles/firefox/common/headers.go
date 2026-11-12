package common

import (
	"strconv"
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/internal/origin"
	"github.com/enetx/surf/profiles"
)

// UserAgent contains Firefox 160 desktop and the existing Firefox 148 mobile UAs.
// All variants read the values for their operating system. iOS uses the FxiOS UA.
var UserAgent = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0",
	profiles.MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:160.0) Gecko/20100101 Firefox/160.0",
	profiles.Linux:   "Mozilla/5.0 (X11; Linux x86_64; rv:160.0) Gecko/20100101 Firefox/160.0",
	profiles.Android: "Mozilla/5.0 (Android 16; Mobile; rv:148.0) Gecko/148.0 Firefox/148.0",
	profiles.IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/148.0 Mobile/15E148 Safari/605.1.15",
}

// Headers applies the desktop HTTP/2 preset to an ordered map, preserving
// nonempty supplied values. Pass a plain HTTP method. BuildRequestHeaders selects
// the target OS, protocol and request-body context explicitly.
var Headers = profiles.NewRequestHeadersApplier(BuildRequestHeaders)

// MobileHeaders applies the Firefox 148 Android placeholder preset. Its default
// identity is Android; nonempty supplied field values remain intact.
var MobileHeaders = profiles.NewRequestHeadersApplier(func(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	ctx.OS = profiles.Android
	return BuildPlaceholderRequestHeaders(ctx)
})

// IOSHeaders applies the Firefox 148 iOS placeholder preset. Its default identity
// is iOS; nonempty supplied field values remain intact.
var IOSHeaders = profiles.NewRequestHeadersApplier(func(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	ctx.OS = profiles.IOS
	return BuildPlaceholderRequestHeaders(ctx)
})

// BuildDesktopHeaders constructs the Firefox 160 desktop identity fragment.
func BuildDesktopHeaders(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	return BuildHeaders(os, "en-US,en;q=0.9")
}

// BuildMobileHeaders constructs the unchanged Firefox 148 mobile identity.
func BuildMobileHeaders(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	return BuildHeaders(os, "en-US,en;q=0.5")
}

// BuildHeaders constructs an identity fragment without method or protocol fields.
// BuildRequestHeaders supplies the complete request declaration and ordering.
func BuildHeaders(os profiles.OSKey, language g.String) *g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	h.Insert(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	h.Insert(header.ACCEPT_LANGUAGE, language)
	h.Insert(header.USER_AGENT, UserAgent.Get(os).UnwrapOrDefault())

	return &h
}

// BuildPlaceholderRequestHeaders preserves the Firefox 148 Android/iOS header
// template. It does not inherit Firefox 160 desktop connection defaults or claim
// current native mobile behavior. The two platforms select independent UAs.
func BuildPlaceholderRequestHeaders(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	defaults := BuildMobileHeaders(ctx.OS)

	h := g.NewMapOrd[g.String, g.String]()
	for _, name := range pseudoHeaderOrder(ctx.Protocol) {
		h.Insert(g.String(name), "")
	}

	h.Insert(header.USER_AGENT, defaults.Get(header.USER_AGENT).UnwrapOrDefault())

	if ctx.Navigation() {
		h.Insert(header.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	} else {
		h.Insert(header.ACCEPT, "*/*")
	}

	h.Insert(header.ACCEPT_LANGUAGE, defaults.Get(header.ACCEPT_LANGUAGE).UnwrapOrDefault())
	h.Insert(header.ACCEPT_ENCODING, defaults.Get(header.ACCEPT_ENCODING).UnwrapOrDefault())
	h.Insert(header.REFERER, "")

	entity := ctx.Request != nil && ctx.Request.Method != "" && ctx.Request.Method != http.MethodGet &&
		ctx.Request.Method != http.MethodHead

	if entity || !ctx.Navigation() {
		h.Insert(header.CONTENT_TYPE, "")
	}

	h.Insert(header.AUTHORIZATION, "")

	if entity || !ctx.Navigation() {
		h.Insert(header.CONTENT_LENGTH, "")
		h.Insert(header.ORIGIN, "")
	}

	h.Insert(header.COOKIE, "")

	if ctx.Navigation() {
		h.Insert(header.UPGRADE_INSECURE_REQUESTS, "1")
		h.Insert(header.SEC_FETCH_DEST, "document")
		h.Insert(header.SEC_FETCH_MODE, "navigate")
		h.Insert(header.SEC_FETCH_SITE, "none")
		h.Insert(header.SEC_FETCH_USER, "?1")
		h.Insert(header.PRIORITY, "u=0, i")
	} else {
		h.Insert(header.SEC_FETCH_DEST, "empty")
		h.Insert(header.SEC_FETCH_MODE, "cors")
		h.Insert(header.SEC_FETCH_SITE, "same-origin")
		h.Insert(header.PRIORITY, "u=1, i")

		if entity {
			h.Insert(header.PRAGMA, "no-cache")
			h.Insert(header.CACHE_CONTROL, "no-cache")
		}
	}

	return h
}

// BuildRequestHeaders constructs fresh Firefox 160 defaults in wire order.
// Protocol zero supplies logical defaults; the actual transport selects
// Connection, TE and Alt-Used. Empty fields reserve optional positions.
// The request and its body are never changed.
func BuildRequestHeaders(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	if ctx.Navigation() {
		return NavigationHeaders(ctx)
	}

	return FetchHeaders(ctx)
}

// HeaderPriority selects Firefox 160 desktop's HTTP/2 HEADERS priority from the
// same navigation/fetch context as the header preset. Ordinary fetch uses normal
// channel priority (encoded weight 21, wire weight 22); document navigation uses
// highest channel priority (encoded 41, wire 42). Both depend on stream zero and
// are nonexclusive. A literal Priority header does not change channel priority.
// The request view, its headers and its context are never mutated.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/dom/fetch/InternalRequest.h#L496
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/modules/libpref/init/StaticPrefList.yaml#L15696-L15712
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2StreamBase.cpp#L119-L129
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2StreamBase.cpp#L920-L931
func HeaderPriority(info http2.PriorityRequest) http2.PriorityParam {
	req := &http.Request{Method: info.Method, URL: info.URL, Header: http.Header(info.Header)}
	if info.Context != nil {
		req = req.WithContext(info.Context)
	}

	ctx := profiles.HeaderContext{Request: req, Protocol: 2}
	weight := uint8(21)
	if ctx.Navigation() {
		weight = 41
	}

	return http2.PriorityParam{Weight: weight}
}

// NavigationHeaders declares Firefox 160 document-request defaults. Form upload
// fields precede Connection and Referer; ordinary GET navigation has no upload.
// Applications can suppress Sec-Fetch-User for navigation without activation.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpHandler.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/HttpBaseChannel.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpChannel.cpp
func NavigationHeaders(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	h := requestHeaders(ctx, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if ctx.HasBody() {
		h.Insert(header.CONTENT_TYPE, "")
		h.Insert(header.CONTENT_LENGTH, "")
		h.Insert(header.ORIGIN, "")
	}

	connectionHeader(&h, ctx)

	h.Insert(header.REFERER, "")
	h.Insert(header.AUTHORIZATION, "")
	h.Insert(header.COOKIE, "")
	h.Insert(header.UPGRADE_INSECURE_REQUESTS, "1")
	h.Insert(header.SEC_FETCH_DEST, "document")
	h.Insert(header.SEC_FETCH_MODE, "navigate")
	h.Insert(header.SEC_FETCH_SITE, "none")
	h.Insert(header.SEC_FETCH_USER, "?1")
	h.Insert(header.PRIORITY, "u=0, i")

	trailingHeaders(&h, ctx)
	applyOriginDefaults(&h, ctx)

	return h
}

// FetchHeaders declares Firefox 160 fetch defaults independently of HTTP method.
// A normal fetch has urgency 4 and is not incremental. Upload length follows its
// Content-Type; a bodyless POST/PUT receives its zero length at the end instead.
// Caller-supplied cache headers retain slots without inventing cache directives.
// User activation can change urgency; explicit Priority values retain ownership.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/dom/fetch/FetchDriver.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/HttpBaseChannel.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpHandler.cpp#L947
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpChannel.cpp#L856
func FetchHeaders(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	h := requestHeaders(ctx, "*/*")
	h.Insert(header.REFERER, "")
	h.Insert(header.CONTENT_TYPE, "")
	h.Insert(header.AUTHORIZATION, "")

	if ctx.HasBody() {
		h.Insert(header.CONTENT_LENGTH, "")
	}

	h.Insert(header.ORIGIN, "")

	connectionHeader(&h, ctx)

	h.Insert(header.COOKIE, "")
	h.Insert(header.SEC_FETCH_DEST, "empty")
	h.Insert(header.SEC_FETCH_MODE, "cors")
	h.Insert(header.SEC_FETCH_SITE, "same-origin")
	h.Insert(header.PRIORITY, "u=4")
	h.Insert(header.PRAGMA, "")
	h.Insert(header.CACHE_CONTROL, "")

	trailingHeaders(&h, ctx)
	applyOriginDefaults(&h, ctx)

	return h
}

// applyOriginDefaults limits generated metadata and encodings to their normal
// browser URL scope. Empty slots retain ordering without emitting defaults;
// runtime merging preserves fields explicitly supplied by the application.
// Nil URLs describe standalone preset templates and keep their normal defaults.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/dom/security/SecFetch.cpp#L378
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/HttpBaseChannel.cpp#L326
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpHandler.cpp#L815
func applyOriginDefaults(h *g.MapOrd[g.String, g.String], ctx profiles.HeaderContext) {
	if ctx.Request == nil || ctx.Request.URL == nil || origin.TrustworthyHTTP(ctx.Request.URL) {
		return
	}

	for _, name := range []g.String{header.SEC_FETCH_DEST, header.SEC_FETCH_MODE, header.SEC_FETCH_SITE, header.SEC_FETCH_USER} {
		if h.Contains(name) {
			h.Insert(name, "")
		}
	}

	h.Insert(header.ACCEPT_ENCODING, "gzip, deflate")
}

func requestHeaders(ctx profiles.HeaderContext, accept g.String) g.MapOrd[g.String, g.String] {
	defaults := BuildDesktopHeaders(ctx.OS)

	h := g.NewMapOrd[g.String, g.String]()
	for _, name := range pseudoHeaderOrder(ctx.Protocol) {
		h.Insert(g.String(name), "")
	}

	h.Insert(header.USER_AGENT, defaults.Get(header.USER_AGENT).UnwrapOrDefault())
	h.Insert(header.ACCEPT, accept)
	h.Insert(header.ACCEPT_LANGUAGE, defaults.Get(header.ACCEPT_LANGUAGE).UnwrapOrDefault())
	h.Insert(header.ACCEPT_ENCODING, defaults.Get(header.ACCEPT_ENCODING).UnwrapOrDefault())

	if ctx.Protocol == 3 {
		h.Insert(header.ALT_USED, "")
	}

	return h
}

func connectionHeader(h *g.MapOrd[g.String, g.String], ctx profiles.HeaderContext) {
	if ctx.Protocol != 1 {
		return
	}

	connection := g.String("keep-alive")
	if ctx.Request != nil && ctx.Request.Close {
		connection = "close"
	}

	h.Insert(header.CONNECTION, connection)
}

// Bodyless POST/PUT receive Content-Length only when the transaction is flattened.
// HTTP/2 then adds its TE default while encoding the field block.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttp.cpp#L496
func trailingHeaders(h *g.MapOrd[g.String, g.String], ctx profiles.HeaderContext) {
	if !ctx.HasBody() && ctx.Request != nil &&
		(ctx.Request.Method == http.MethodPost || ctx.Request.Method == http.MethodPut) {
		h.Insert(header.CONTENT_LENGTH, "")
	}

	if ctx.Protocol == 2 {
		h.Insert(header.TE, "trailers")
	}
}

// ProtocolHeaders applies protocol defaults from the desktop request factory.
// Its header-only signature uses GET unless a method pseudo-field is supplied;
// explicit Fetch Metadata and content length still describe the request context.
// Explicit regular, pseudo and case metadata remain caller-owned. Use the typed
// BuildRequestHeaders context for full method, body and protocol selection.
func ProtocolHeaders(headers http.Header, major int) {
	if major < 1 || major > 3 {
		return
	}

	req := &http.Request{Method: http.MethodGet, Header: headers}

	for name, values := range headers {
		if len(values) == 0 {
			continue
		}

		if name == ":method" && values[0] != "" {
			req.Method = values[0]
		}

		if strings.EqualFold(name, header.CONTENT_LENGTH) {
			if length, err := strconv.ParseInt(values[0], 10, 64); err == nil && length > 0 {
				req.ContentLength = length
			}
		}
	}

	defaults := BuildRequestHeaders(profiles.HeaderContext{Request: req, Protocol: major})

	for _, name := range []string{header.CONNECTION, header.TE} {
		if value := defaults.Get(g.String(name)); value.IsSome() {
			setDefaultHeader(headers, name, value.Unwrap().Std())
		}
	}

	var regular, pseudo []string
	for name := range defaults.Iter().Keys() {
		if strings.HasPrefix(name.Std(), ":") {
			pseudo = append(pseudo, name.Std())
		} else {
			regular = append(regular, name.Std())
		}
	}

	if _, explicit := headers[http.HeaderOrderKey]; !explicit {
		headers[http.HeaderOrderKey] = regular
	}

	if major > 1 {
		if _, explicit := headers[http.PHeaderOrderKey]; !explicit {
			headers[http.PHeaderOrderKey] = pseudo
		}
	}
}

func setDefaultHeader(headers http.Header, name, value string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return
		}
	}

	headers.Set(name, value)
}

// pseudoHeaderOrder returns independent protocol defaults for every caller.
func pseudoHeaderOrder(protocol int) []string {
	if protocol == 3 {
		return []string{":method", ":scheme", ":authority", ":path"}
	}

	return []string{":method", ":path", ":authority", ":scheme"}
}
