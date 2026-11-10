package quic

import "github.com/enetx/surf/profiles"

// ConfigureRequestBody follows Chromium's upload buffer bounds. The packet
// constant is a sizing heuristic, not a guarantee about packet boundaries.
// https://github.com/chromium/chromium/blob/156.0.8078.79/net/quic/quic_http_stream.cc
// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_constants.h
func ConfigureRequestBody(h profiles.H3Config) {
	h.RequestBodyBufferSizePolicy(requestBodyBufferSize)
}

func requestBodyBufferSize(length int64) int {
	return int(min(max(length, 10*1452), 256*1452))
}
