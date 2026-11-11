package quic

import (
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf/profiles"
)

// Default QUICHE receive policy, without negotiated ACK_FREQUENCY or optional
// AKD3/AKDU/1ACK connection options. The transition uses packet-number span.
// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_received_packet_manager.cc
// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/common/quiche_protocol_flags_list.h
func configureAck(q profiles.QUICConfig) {
	q.AckPacketThreshold(2).AckDecimation(100, 10).
		AckDelayRTTDivisor(4).MinAckDelay(time.Millisecond).
		AckReordering(quic.AckReorderingWindow).AckMissingPacketLimit(4).
		AckECN(quic.AckECNTransitions)
}
