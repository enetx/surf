package quic

import "github.com/enetx/quic-go"

// StreamLossRetention selects whether a lost STREAM packet can still supply ACKs.
// Chromium retains lost transmission metadata until an ACK reaches the first packet sent after the loss.
// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_unacked_packet_map.cc
func StreamLossRetention(info quic.StreamLossInfo) bool {
	return info.FirstPacketAfterLoss < 0 || info.LargestAcknowledged < info.FirstPacketAfterLoss
}
