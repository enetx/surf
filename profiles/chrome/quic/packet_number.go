package quic

import (
	"math/bits"

	"github.com/enetx/quic-go"
)

// PacketNumberLength follows QUICHE's UpdatePacketNumberLength, including its
// congestion-window estimate and the soft limit left by packet coalescing.
// The transport independently enforces safe bounds.
// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_packet_creator.cc
// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_sent_packet_manager.h
// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_connection.cc
func PacketNumberLength(info quic.PacketNumberLengthInfo) uint8 {
	delta := max(info.PacketNumber-info.LeastUnacknowledged, info.MaxPacketsInFlight, info.CoalescedMaxPacketsInFlight)
	return uint8(min(4, max(1, (bits.Len64(delta*4)+7)/8)))
}
