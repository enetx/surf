package surf

import "github.com/enetx/quic-go"

type (
	PeerAckFrequency       = quic.PeerAckFrequency
	PeerAckFrequencyInfo   = quic.PeerAckFrequencyInfo
	PeerAckFrequencyPolicy = quic.PeerAckFrequencyPolicy
)

// PeerAckFrequencyPolicy selects outgoing legacy ACK_FREQUENCY requests after
// the peer advertises support. The callback receives live window, MTU and RTT
// state plus the last acknowledged request. Nil disables sending; local receive
// policy and its LegacyAckFrequency advertisement remain independent.
func (q *QUICSettings) PeerAckFrequencyPolicy(policy PeerAckFrequencyPolicy) *QUICSettings {
	q.handshake().PeerAckFrequencyPolicy = policy
	return q
}

// InitialCongestionWindowPackets sets the initial send window in datagram-sized
// packets. Zero restores the engine default; supported explicit values are 2..10000.
func (q *QUICSettings) InitialCongestionWindowPackets(packets uint32) *QUICSettings {
	q.handshake().InitialCongestionWindowPackets = packets
	return q
}
