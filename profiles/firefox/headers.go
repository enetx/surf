package firefox

import (
	"net/http"

	"github.com/enetx/g"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
)

// --- Header order maps -------------------------------------------------------

var headerOrderDesktop = g.Map[string, g.Slice[string]]{
	http.MethodGet: {
		":method",
		":path",
		":authority",
		":scheme",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.AUTHORIZATION,
		header.COOKIE,
		header.UPGRADE_INSECURE_REQUESTS,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.SEC_FETCH_USER,
		header.PRIORITY,
	},

	http.MethodGet + "http3": {
		":method",
		":scheme",
		":authority",
		":path",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.AUTHORIZATION,
		header.COOKIE,
		header.UPGRADE_INSECURE_REQUESTS,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.SEC_FETCH_USER,
		header.PRIORITY,
	},

	http.MethodPost: {
		":method",
		":path",
		":authority",
		":scheme",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.CONTENT_TYPE,
		header.AUTHORIZATION,
		header.CONTENT_LENGTH,
		header.ORIGIN,
		header.COOKIE,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.PRIORITY,
		header.PRAGMA,
		header.CACHE_CONTROL,
	},

	http.MethodPost + "http3": {
		":method",
		":scheme",
		":authority",
		":path",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.CONTENT_TYPE,
		header.AUTHORIZATION,
		header.CONTENT_LENGTH,
		header.ORIGIN,
		header.COOKIE,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.PRIORITY,
		header.PRAGMA,
		header.CACHE_CONTROL,
	},
}

// headerOrderMobile is a placeholder mobile variant. On the day real Firefox Android header
// ordering is observed, this map is the single point to substitute it without touching desktop.
// The literal is a physical copy of headerOrderDesktop so the two maps can diverge independently.
var headerOrderMobile = g.Map[string, g.Slice[string]]{
	http.MethodGet: {
		":method",
		":path",
		":authority",
		":scheme",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.AUTHORIZATION,
		header.COOKIE,
		header.UPGRADE_INSECURE_REQUESTS,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.SEC_FETCH_USER,
		header.PRIORITY,
	},

	http.MethodGet + "http3": {
		":method",
		":scheme",
		":authority",
		":path",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.AUTHORIZATION,
		header.COOKIE,
		header.UPGRADE_INSECURE_REQUESTS,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.SEC_FETCH_USER,
		header.PRIORITY,
	},

	http.MethodPost: {
		":method",
		":path",
		":authority",
		":scheme",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.CONTENT_TYPE,
		header.AUTHORIZATION,
		header.CONTENT_LENGTH,
		header.ORIGIN,
		header.COOKIE,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.PRIORITY,
		header.PRAGMA,
		header.CACHE_CONTROL,
	},

	http.MethodPost + "http3": {
		":method",
		":scheme",
		":authority",
		":path",
		header.USER_AGENT,
		header.ACCEPT,
		header.ACCEPT_LANGUAGE,
		header.ACCEPT_ENCODING,
		header.REFERER,
		header.CONTENT_TYPE,
		header.AUTHORIZATION,
		header.CONTENT_LENGTH,
		header.ORIGIN,
		header.COOKIE,
		header.SEC_FETCH_DEST,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_SITE,
		header.PRIORITY,
		header.PRAGMA,
		header.CACHE_CONTROL,
	},
}

var headerCache = profiles.NewHeaderCache(headerOrderDesktop, headerOrderMobile)

// --- Static header set (Variant.BuildHeaders) --------------------------------

// buildHeadersDesktop constructs the desktop Firefox 148 request header set.
// Firefox does not emit Client Hints UA-CH headers (sec-ch-ua / sec-ch-ua-mobile /
// sec-ch-ua-platform).
func buildHeadersDesktop(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	h.Insert(":authority", "")
	h.Insert(":method", "")
	h.Insert(":path", "")
	h.Insert(":scheme", "")
	h.Insert(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	h.Insert(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5")
	h.Insert(header.AUTHORIZATION, "")
	h.Insert(header.COOKIE, "")
	h.Insert(header.ORIGIN, "")
	h.Insert(header.REFERER, "")
	h.Insert(header.USER_AGENT, UserAgent.Get(os).UnwrapOrDefault())

	return &h
}

// buildHeadersMobile constructs the placeholder mobile Firefox 148 request header set.
// On the day real Firefox Android header set diverges from desktop, replace this body — it is
// the single point of substitution for the entire mobile header set.
func buildHeadersMobile(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	h.Insert(":authority", "")
	h.Insert(":method", "")
	h.Insert(":path", "")
	h.Insert(":scheme", "")
	h.Insert(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	h.Insert(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5")
	h.Insert(header.AUTHORIZATION, "")
	h.Insert(header.COOKIE, "")
	h.Insert(header.ORIGIN, "")
	h.Insert(header.REFERER, "")
	h.Insert(header.USER_AGENT, UserAgent.Get(os).UnwrapOrDefault())

	return &h
}

// --- Per-request header pipeline (Variant.Headers) ---------------------------

// DesktopApplier applies the desktop Firefox request-header pipeline. Wired into firefox.Desktop.
var DesktopApplier = profiles.NewApplier(insertDesktopHeaders, insertDesktopHeaders, headerCache, false)

// MobileApplier applies the mobile Firefox request-header pipeline. Wired into firefox.Mobile.
var MobileApplier = profiles.NewApplier(insertMobileHeaders, insertMobileHeaders, headerCache, true)

func insertDesktopHeaders[T ~string](headers *g.MapOrd[T, T], method string) {
	switch method {
	case http.MethodPost:
		headers.Insert(header.ACCEPT, "*/*")
		headers.Insert(header.CACHE_CONTROL, "no-cache")
		headers.Insert(header.CONTENT_TYPE, "")
		headers.Insert(header.CONTENT_LENGTH, "")
		headers.Insert(header.PRAGMA, "no-cache")
		headers.Insert(header.PRIORITY, "u=1, i")
		headers.Insert(header.SEC_FETCH_DEST, "empty")
		headers.Insert(header.SEC_FETCH_MODE, "cors")
		headers.Insert(header.SEC_FETCH_SITE, "same-origin")
	default:
		headers.Insert(header.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		headers.Insert(header.PRIORITY, "u=0, i")
		headers.Insert(header.SEC_FETCH_DEST, "document")
		headers.Insert(header.SEC_FETCH_MODE, "navigate")
		headers.Insert(header.SEC_FETCH_SITE, "none")
		headers.Insert(header.SEC_FETCH_USER, "?1")
		headers.Insert(header.UPGRADE_INSECURE_REQUESTS, "1")
	}
}

// insertMobileHeaders is a placeholder mobile variant. On the day the real Firefox Android header
// inserts diverge from desktop, this function is the single point to substitute them.
func insertMobileHeaders[T ~string](headers *g.MapOrd[T, T], method string) {
	switch method {
	case http.MethodPost:
		headers.Insert(header.ACCEPT, "*/*")
		headers.Insert(header.CACHE_CONTROL, "no-cache")
		headers.Insert(header.CONTENT_TYPE, "")
		headers.Insert(header.CONTENT_LENGTH, "")
		headers.Insert(header.PRAGMA, "no-cache")
		headers.Insert(header.PRIORITY, "u=1, i")
		headers.Insert(header.SEC_FETCH_DEST, "empty")
		headers.Insert(header.SEC_FETCH_MODE, "cors")
		headers.Insert(header.SEC_FETCH_SITE, "same-origin")
	default:
		headers.Insert(header.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		headers.Insert(header.PRIORITY, "u=0, i")
		headers.Insert(header.SEC_FETCH_DEST, "document")
		headers.Insert(header.SEC_FETCH_MODE, "navigate")
		headers.Insert(header.SEC_FETCH_SITE, "none")
		headers.Insert(header.SEC_FETCH_USER, "?1")
		headers.Insert(header.UPGRADE_INSECURE_REQUESTS, "1")
	}
}
