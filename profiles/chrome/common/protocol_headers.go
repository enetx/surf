package common

import (
	"slices"
	"strings"

	"github.com/enetx/http"
	"github.com/enetx/surf/header"
)

// RequestHeaders applies Chrome's defaults for the transport actually selected.
// HTTP/1.1 has Connection and lowercase Client Hints, while Priority belongs to
// multiplexed transports. Explicit request values and pseudo-header order win.
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/http/http_network_transaction.cc
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/http/http_request_headers.cc
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/spdy/spdy_http_utils.cc
func RequestHeaders(req *http.Request, major int) {
	h := req.Header

	if major != 1 {
		if _, explicit := h[http.PHeaderOrderKey]; !explicit {
			h[http.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
		}

		priority := "u=0, i"
		if req.Method == http.MethodPost {
			priority = "u=1, i"
		}

		setDefaultHeader(h, header.PRIORITY, priority)
		if !hasOrderedHeader(h, header.PRIORITY) {
			h[http.HeaderOrderKey] = append(h[http.HeaderOrderKey], header.PRIORITY)
		}

		return
	}

	connection := "keep-alive"
	if req.Close {
		connection = "close"
	}

	setDefaultHeader(h, header.CONNECTION, connection)
	order := h[http.HeaderOrderKey]

	if !hasOrderedHeader(h, header.CONNECTION) {
		pos := slices.IndexFunc(order, func(name string) bool { return strings.EqualFold(name, header.HOST) })
		h[http.HeaderOrderKey] = slices.Insert(order, pos+1, header.CONNECTION)
	}

	if _, explicit := h[http.HeaderCaseKey]; !explicit {
		h[http.HeaderCaseKey] = []string{header.SEC_CH_UA, header.SEC_CH_UA_MOBILE, header.SEC_CH_UA_PLATFORM}
	}
}

func setDefaultHeader(h http.Header, name, value string) {
	for key := range h {
		if strings.EqualFold(key, name) {
			return
		}
	}

	h.Set(name, value)
}

func hasOrderedHeader(h http.Header, name string) bool {
	return slices.ContainsFunc(h[http.HeaderOrderKey], func(key string) bool { return strings.EqualFold(key, name) })
}
