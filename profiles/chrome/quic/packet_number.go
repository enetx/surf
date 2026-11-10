package quic

import (
	"math/bits"

	"github.com/enetx/quic-go"
)

// PacketNumberLength follows QUICHE's UpdatePacketNumberLength, including its
// congestion-window estimate. The transport independently enforces safe bounds.
// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_packet_creator.cc
// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_sent_packet_manager.h
func PacketNumberLength(info quic.PacketNumberLengthInfo) uint8 {
	delta := max(info.PacketNumber-info.LeastUnacknowledged, info.MaxPacketsInFlight)
	return uint8(min(4, max(1, (bits.Len64(delta*4)+7)/8)))
}
