package quic

import (
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/profiles"
)

// ConfigureQPACK follows Neqo's encoder-before-decoder order and initial type
// writes. Capacity updates are queued after processing the peer's SETTINGS.
func ConfigureQPACK(h profiles.H3Config) {
	h.QpackStreamOrder(http3.QPACKEncoderStream, http3.QPACKDecoderStream).
		QpackEagerStreamTypes(true).
		QpackEncoderTableCapacity(65536).
		QpackEncoderCapacityTiming(http3.QPACKCapacityOnSettings)
}
