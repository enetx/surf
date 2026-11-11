package quic

import "github.com/enetx/surf/profiles"

// ConfigureRequestBody follows Chromium's upload buffer bounds. The packet
// constant is a sizing heuristic, not a guarantee about packet boundaries.
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/quic/quic_http_stream.cc
// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_constants.h
func ConfigureRequestBody(h profiles.H3Config) {
	h.RequestBodyBufferSizePolicy(requestBodyBufferSize)
}

func requestBodyBufferSize(length int64) int {
	return int(min(max(length, 10*1452), 256*1452))
}
