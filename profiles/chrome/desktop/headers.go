package desktop

import (
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
)

// Header order and request defaults for Chrome desktop.
var headerOrder = g.Map[string, g.Slice[string]]{
	http.MethodGet: {
		":method",
		":authority",
		":scheme",
		":path",
		header.SEC_CH_UA,
		header.SEC_CH_UA_MOBILE,
		header.SEC_CH_UA_PLATFORM,
		header.AUTHORIZATION,
		header.UPGRADE_INSECURE_REQUESTS,
		header.USER_AGENT,
		header.ACCEPT,
		header.SEC_FETCH_SITE,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_USER,
		header.SEC_FETCH_DEST,
		header.REFERER,
		header.ACCEPT_ENCODING,
		header.ACCEPT_LANGUAGE,
		header.COOKIE,
		header.PRIORITY,
	},

	http.MethodGet + "http3": {
		":method",
		":authority",
		":scheme",
		":path",
		header.SEC_CH_UA,
		header.SEC_CH_UA_MOBILE,
		header.SEC_CH_UA_PLATFORM,
		header.AUTHORIZATION,
		header.UPGRADE_INSECURE_REQUESTS,
		header.USER_AGENT,
		header.ACCEPT,
		header.SEC_FETCH_SITE,
		header.SEC_FETCH_MODE,
		header.SEC_FETCH_USER,
		header.SEC_FETCH_DEST,
		header.REFERER,
		header.ACCEPT_ENCODING,
		header.ACCEPT_LANGUAGE,
		header.COOKIE,
		header.PRIORITY,
	},

	http.MethodPost: {
		":method",
		":authority",
		":scheme",
		":path",
		header.CONTENT_LENGTH,
		header.PRAGMA,
		header.CACHE_CONTROL,
		header.SEC_CH_UA_PLATFORM,
		header.AUTHORIZATION,
		header.USER_AGENT,
		header.SEC_CH_UA,
		header.CONTENT_TYPE,
		header.SEC_CH_UA_MOBILE,
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
	},

	http.MethodPost + "http3": {
		":method",
		":authority",
		":scheme",
		":path",
		header.CONTENT_LENGTH,
		header.PRAGMA,
		header.CACHE_CONTROL,
		header.SEC_CH_UA_PLATFORM,
		header.AUTHORIZATION,
		header.USER_AGENT,
		header.SEC_CH_UA,
		header.CONTENT_TYPE,
		header.SEC_CH_UA_MOBILE,
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
	h.Insert(header.SEC_CH_UA, common.SecCHUA)
	h.Insert(header.SEC_CH_UA_MOBILE, os.Mobile())
	h.Insert(header.SEC_CH_UA_PLATFORM, common.Platform.Get(os).UnwrapOrDefault())
	h.Insert(header.USER_AGENT, common.UserAgent.Get(os).UnwrapOrDefault())

	return &h
}

func insertHeaders[T ~string](headers *g.MapOrd[T, T], method string) {
	// Reserve its position; the selected protocol supplies the actual default.
	if !headers.Contains(header.PRIORITY) {
		headers.Insert(header.PRIORITY, "")
	}
	switch strings.TrimSuffix(method, "http3") {
	case http.MethodPost:
		headers.Insert(header.ACCEPT, "*/*")
		headers.Insert(header.CONTENT_TYPE, "")
		headers.Insert(header.CONTENT_LENGTH, "")
		headers.Insert(header.SEC_FETCH_DEST, "empty")
		headers.Insert(header.SEC_FETCH_MODE, "cors")
		headers.Insert(header.SEC_FETCH_SITE, "same-origin")
	default:
		headers.Insert(
			header.ACCEPT,
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		)
		headers.Insert(header.SEC_FETCH_DEST, "document")
		headers.Insert(header.SEC_FETCH_MODE, "navigate")
		headers.Insert(header.SEC_FETCH_SITE, "none")
		headers.Insert(header.SEC_FETCH_USER, "?1")
		headers.Insert(header.UPGRADE_INSECURE_REQUESTS, "1")
	}
}
