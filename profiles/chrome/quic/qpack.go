package quic

import (
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/profiles"
)

// ConfigureQPACK follows Chromium's stream reservation and deferred flush policy.
// Creating a stream does not send its type until the first instruction is queued.
func ConfigureQPACK(h profiles.H3Config) {
	// Cookie splitting belongs to the HTTP/3 header encoder. Initial priority
	// updates belong to QuicSpdyStream and are separate from GREASE frames.
	// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/qpack/value_splitting_header_list.cc
	// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/http/quic_spdy_stream.cc
	h.QpackSplitCookies(true).
		PriorityUpdates(true).
		ControlGreaseFramesFactory(NewControlGreaseFrames).
		QpackStreamOrder(http3.QPACKDecoderStream, http3.QPACKEncoderStream).
		QpackEagerStreamTypes(false).
		QpackEncoderTableCapacity(65536).
		QpackEncoderCapacityTiming(http3.QPACKCapacityBeforeHeaders)
}
