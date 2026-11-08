package ios

import (
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
)

// iOS uses the same header order for navigation and fetch requests.
var headerOrder = g.Map[string, g.Slice[string]]{
	http.MethodGet: {
		":method", ":scheme", ":authority", ":path",
		header.SEC_FETCH_DEST,
		header.USER_AGENT,
		header.ACCEPT,
		header.SEC_FETCH_SITE,
		header.SEC_FETCH_MODE,
		header.ACCEPT_LANGUAGE,
		header.PRIORITY,
		header.ACCEPT_ENCODING,
		header.SEC_FETCH_USER,
		header.REFERER,
		header.COOKIE,
		header.CONTENT_TYPE,
		header.CONTENT_LENGTH,
		header.ORIGIN,
		header.AUTHORIZATION,
	},
}

var headerCache = profiles.NewHeaderCache(headerOrder, headerOrder)

// Headers applies the iOS request-header pipeline.
var Headers = profiles.NewApplier(insertHeaders, insertHeaders, headerCache, true)

// BuildHeaders constructs the iOS request header set.
func BuildHeaders(_ profiles.OSKey) *g.MapOrd[g.String, g.String] {
	h := g.NewMapOrd[g.String, g.String]()
	h.Insert(":method", "")
	h.Insert(":scheme", "")
	h.Insert(":authority", "")
	h.Insert(":path", "")
	h.Insert(header.USER_AGENT, common.UserAgent.Get(profiles.IOS).UnwrapOrDefault())
	h.Insert(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	h.Insert(header.ACCEPT_LANGUAGE, "en-US,en;q=0.9")
	h.Insert(header.AUTHORIZATION, "")
	h.Insert(header.COOKIE, "")
	h.Insert(header.ORIGIN, "")
	h.Insert(header.REFERER, "")
	return &h
}

func insertHeaders[T ~string](headers *g.MapOrd[T, T], method string) {
	if strings.TrimSuffix(method, "http3") == http.MethodPost {
		headers.Insert(header.ACCEPT, "*/*")
		headers.Insert(header.CONTENT_TYPE, "")
		headers.Insert(header.CONTENT_LENGTH, "")
		headers.Insert(header.PRIORITY, "u=1, i")
		headers.Insert(header.SEC_FETCH_DEST, "empty")
		headers.Insert(header.SEC_FETCH_MODE, "cors")
		headers.Insert(header.SEC_FETCH_SITE, "same-origin")
		return
	}
	headers.Insert(header.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	headers.Insert(header.PRIORITY, "u=0, i")
	headers.Insert(header.SEC_FETCH_DEST, "document")
	headers.Insert(header.SEC_FETCH_MODE, "navigate")
	headers.Insert(header.SEC_FETCH_SITE, "none")
}
