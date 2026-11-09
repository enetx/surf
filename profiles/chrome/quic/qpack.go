package quic

import (
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/profiles"
)

// ConfigureQPACK follows Chromium's stream reservation and deferred flush policy.
// Creating a stream does not send its type until the first instruction is queued.
func ConfigureQPACK(h profiles.H3Config) {
	h.QpackStreamOrder(http3.QPACKDecoderStream, http3.QPACKEncoderStream).
		QpackEagerStreamTypes(false).
		QpackEncoderTableCapacity(65536).
		QpackEncoderCapacityTiming(http3.QPACKCapacityBeforeHeaders)
}
