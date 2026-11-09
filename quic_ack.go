package surf

import (
	"time"

	"github.com/enetx/quic-go"
)

type (
	AckReorderingMode = quic.AckReorderingMode
	AckECNMode        = quic.AckECNMode
)

const (
	AckReorderingNative    = quic.AckReorderingNative
	AckReorderingImmediate = quic.AckReorderingImmediate
	AckReorderingWindow    = quic.AckReorderingWindow
	AckECNNative           = quic.AckECNNative
	AckECNTransitions      = quic.AckECNTransitions
	AckECNCountOnly        = quic.AckECNCountOnly
)

func (q *QUICSettings) ackPolicy() *quic.AckPolicy {
	h := q.handshake()
	if h.AckPolicy == nil {
		h.AckPolicy = &quic.AckPolicy{}
	}

	return h.AckPolicy
}

// AckPacketThreshold sets the initial number of ack-eliciting packets per ACK.
// Zero uses the engine's native threshold. Only Application Data is affected.
func (q *QUICSettings) AckPacketThreshold(packets uint64) *QUICSettings {
	q.ackPolicy().PacketThreshold = packets
	return q
}

// AckDecimation selects a new packet threshold once the received packet number
// reaches the smallest received number plus after. It is not a received-packet
// count. A zero threshold disables decimation without negotiating ACK_FREQUENCY.
func (q *QUICSettings) AckDecimation(after, threshold uint64) *QUICSettings {
	p := q.ackPolicy()
	p.DecimationAfter, p.DecimationThreshold = after, threshold
	return q
}

// AckDelayRTTDivisor caps delayed ACKs by minRTT/divisor after decimation.
// Zero disables RTT scaling. MaxAckDelay still supplies the upper bound.
func (q *QUICSettings) AckDelayRTTDivisor(divisor uint32) *QUICSettings {
	q.ackPolicy().RTTDivisor = divisor
	return q
}

// MinAckDelay sets the floor for the RTT-scaled delay, within MaxAckDelay.
func (q *QUICSettings) MinAckDelay(delay time.Duration) *QUICSettings {
	q.ackPolicy().MinDelay = delay
	return q
}

// AckReordering selects how missing/out-of-order packets prompt ACKs.
func (q *QUICSettings) AckReordering(mode AckReorderingMode) *QUICSettings {
	q.ackPolicy().Reordering = mode
	return q
}

// AckMissingPacketLimit bounds immediate ACKs following a gap in Window mode.
func (q *QUICSettings) AckMissingPacketLimit(packets uint64) *QUICSettings {
	q.ackPolicy().MissingPacketAckLimit = packets
	return q
}

// AckECN selects immediate ACKs for CE marks, CE transitions, or counting only.
func (q *QUICSettings) AckECN(mode AckECNMode) *QUICSettings {
	q.ackPolicy().ECN = mode
	return q
}

// ResetAckPolicy restores native receive ACK behavior, retaining MaxAckDelay.
func (q *QUICSettings) ResetAckPolicy() *QUICSettings {
	q.handshake().AckPolicy = nil
	return q
}
