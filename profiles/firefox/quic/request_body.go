package quic

import (
	"strings"

	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/profiles"
)

// ConfigureRequestBody follows Http3Stream's ReadSegmentsAgain size, using
// network.buffer.cache.size preference (custom browser prefs can differ).
// Necko buffers serialized HTTP/1 request headers and the body together, even
// for HTTP/3. The first body segment uses only the space left after the headers.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/Http3Stream.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/base/nsIOService.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/modules/libpref/init/all.js
func ConfigureRequestBody(h profiles.H3Config) {
	h.RequestBodyBufferSize(32768).RequestBodyFirstReadSizePolicy(firstRequestBodyReadSize)
}

// firstRequestBodyReadSize models the input buffer consumed by Http3Stream,
// independently of QPACK compression. Connection is present in Necko's input
// but removed before HTTP/3 field encoding; its bytes consume input buffer space.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/nsHttpRequestHead.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/nsHttpHeaderArray.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/nsHttpHandler.cpp
func firstRequestBodyReadSize(info http3.RequestBodyReadInfo) int {
	method, path, authority := info.Request.Method, info.Request.URL.RequestURI(), info.Request.Host
	if method == "" {
		method = "GET"
	}

	if authority == "" {
		authority = info.Request.URL.Host
	}

	size := 0

	for _, field := range info.HeaderFields {
		switch field.Name {
		case ":method":
			method = field.Value
		case ":path":
			path = field.Value
		case ":authority":
			authority = field.Value
		default:
			if !strings.HasPrefix(field.Name, ":") {
				size += len(field.Name) + len(": ") + len(field.Value) + len("\r\n")
			}
		}
	}

	// Flattened request line, Host and the terminating empty line.
	size += len(method) + len(" ") + len(path) + len(" HTTP/1.1\r\n")
	size += len("Host: ") + len(authority) + len("\r\n") + len("\r\n")
	connection := "keep-alive"

	if info.Request.Close {
		connection = "close"
	}

	for name, values := range info.Request.Header {
		if strings.EqualFold(name, "connection") && len(values) > 0 {
			connection = strings.Join(values, ", ")
			break
		}
	}

	size += len("Connection: ") + len(connection) + len("\r\n")

	return info.BufferSize - size%info.BufferSize
}
