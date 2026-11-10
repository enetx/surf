package quic

import (
	"math/bits"

	"github.com/enetx/quic-go"
)

// PacketNumberLength follows Neqo's full-number encoding before the first ACK
// and twice the unacknowledged range thereafter.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs
func PacketNumberLength(info quic.PacketNumberLengthInfo) uint8 {
	span := info.PacketNumber + 1
	if info.LargestAcknowledged >= 0 {
		span = (info.PacketNumber - uint64(info.LargestAcknowledged)) * 2
	}

	return uint8(min(4, max(1, (bits.Len64(span)+7)/8)))
}
