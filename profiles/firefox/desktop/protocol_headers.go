package desktop

import (
	"slices"
	"strings"

	"github.com/enetx/http"
	"github.com/enetx/surf/header"
)

// ProtocolHeaders follows Firefox's connection-header construction. TE is an
// HTTP/2 default; HTTP/1.1 sends Connection in the position reserved by Necko.
// Pseudo-header defaults follow the selected transport, including fallback.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpHandler.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2Stream.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http3Stream.cpp
func ProtocolHeaders(headers http.Header, major int) {
	switch major {
	case 1:
		setDefaultHeader(headers, header.CONNECTION, "keep-alive")
		order := headers[http.HeaderOrderKey]
		if slices.ContainsFunc(order, func(name string) bool { return strings.EqualFold(name, header.CONNECTION) }) {
			return
		}
		pos := slices.IndexFunc(
			order,
			func(name string) bool { return strings.EqualFold(name, header.ACCEPT_ENCODING) },
		)
		headers[http.HeaderOrderKey] = slices.Insert(order, pos+1, header.CONNECTION)
	case 2:
		if _, explicit := headers[http.PHeaderOrderKey]; !explicit {
			headers[http.PHeaderOrderKey] = []string{":method", ":path", ":authority", ":scheme"}
		}
		setDefaultHeader(headers, header.TE, "trailers")
		order := headers[http.HeaderOrderKey]
		if !slices.ContainsFunc(order, func(name string) bool { return strings.EqualFold(name, header.TE) }) {
			headers[http.HeaderOrderKey] = append(order, header.TE)
		}
	case 3:
		if _, explicit := headers[http.PHeaderOrderKey]; !explicit {
			headers[http.PHeaderOrderKey] = []string{":method", ":scheme", ":authority", ":path"}
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
