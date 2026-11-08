package desktop

import (
	"net/http"
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox/common"
)

// Header order and request defaults for Firefox desktop.
var headerOrder = g.Map[string, g.Slice[string]]{
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
		header.TE,
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
		header.TE,
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

var headerCache = profiles.NewHeaderCache(headerOrder, headerOrder)

// Headers applies the desktop request-header pipeline.
var Headers = profiles.NewApplier(insertHeaders, insertHeaders, headerCache, false)

// BuildHeaders constructs the desktop request header set.
func BuildHeaders(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	h.Insert(":authority", "")
	h.Insert(":method", "")
	h.Insert(":path", "")
	h.Insert(":scheme", "")
	h.Insert(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	h.Insert(header.ACCEPT_LANGUAGE, "en-US,en;q=0.9")
	h.Insert(header.AUTHORIZATION, "")
	h.Insert(header.COOKIE, "")
	h.Insert(header.ORIGIN, "")
	h.Insert(header.REFERER, "")
	h.Insert(header.USER_AGENT, common.UserAgent.Get(os).UnwrapOrDefault())

	return &h
}

func insertHeaders[T ~string](headers *g.MapOrd[T, T], method string) {
	if !strings.HasSuffix(method, "http3") {
		headers.Insert(header.TE, "trailers")
	}
	switch strings.TrimSuffix(method, "http3") {
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
