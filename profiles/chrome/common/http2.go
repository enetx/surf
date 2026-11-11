package common

import (
	"strings"

	"github.com/enetx/http/http2"
)

// HpackPolicy follows Quiche's choice to insert regular fields and :authority,
// but not varying pseudo-fields. Exact static pseudo-fields keep their indexes.
// Oversized incremental literals clear the table instead of changing representation.
// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/http2/hpack/hpack_encoder.cc
func HpackPolicy(name, value string) http2.HPACKRepresentation {
	if name == ":authority" || !strings.HasPrefix(name, ":") {
		return http2.HPACKIncrementalIndexing
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
