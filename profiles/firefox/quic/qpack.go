package quic

import (
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/profiles"
)

// ConfigureQPACK follows Neqo's encoder-before-decoder order and initial type
// writes. Capacity updates are queued after processing the peer's SETTINGS.
func ConfigureQPACK(h profiles.H3Config) {
	// The Firefox header glue preserves Cookie as one field; Neqo does not
	// apply Chromium's cookie crumbling or unconditional QPACK N-bit rules.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/socket/neqo_glue/src/lib.rs
	// Neqo starts with last_send_priority equal to the request's priority.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/third_party/rust/neqo-http3/src/priority.rs
	h.QpackSplitCookies(false).
		PriorityUpdates(false).
		ControlGreaseFramesFactory(NewControlGreaseFrames).
		QpackStreamOrder(http3.QPACKEncoderStream, http3.QPACKDecoderStream).
		QpackEagerStreamTypes(true).
		QpackEncoderTableCapacity(65536).
		QpackEncoderCapacityTiming(http3.QPACKCapacityOnSettings)
}
