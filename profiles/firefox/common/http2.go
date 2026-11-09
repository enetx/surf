package common

import "github.com/enetx/http/http2"

// HpackPolicy follows Http2Compressor::EncodeHeaderBlock / ProcessHeader:
// :path is always a non-indexed literal, authorization is never-indexed, and
// cookie-pairs shorter than 20 bytes are never-indexed. Length is in bytes.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/Http2Compression.cpp
func HpackPolicy(name, value string) http2.HPACKRepresentation {
	switch {
	case name == ":path":
		return http2.HPACKWithoutIndexing
	case name == "authorization" || name == "cookie" && len(value) < 20:
		return http2.HPACKNeverIndex
	default:
		return http2.HPACKDefault
	}
}

// HpackIndexingLimit applies Mozilla's insertion size rule without disabling
// references to entries that are already in the encoder table.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/Http2Compression.cpp
func HpackIndexingLimit(tableCapacity uint32) uint32 {
	if tableCapacity < 128 {
		return 0
	}

	return tableCapacity / 2
}
