package common

import (
	"strings"

	"github.com/enetx/http/http2"
)

// HpackPolicy follows Quiche's choice to insert regular fields and :authority,
// but not varying pseudo-fields. Exact static pseudo-fields keep their indexes.
// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/http2/hpack/hpack_encoder.cc
func HpackPolicy(name, value string) http2.HPACKRepresentation {
	if name == ":authority" || !strings.HasPrefix(name, ":") {
		return http2.HPACKDefault
	}

	switch name {
	case ":path":
		if value == "/" || value == "/index.html" {
			return http2.HPACKDefault
		}
	case ":method":
		if value == "GET" || value == "POST" {
			return http2.HPACKDefault
		}
	case ":scheme":
		if value == "http" || value == "https" {
			return http2.HPACKDefault
		}
	}

	return http2.HPACKWithoutIndexing
}
