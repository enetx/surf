package surf

import (
	"time"

	"github.com/enetx/quic-go"
)

type PacingAlgorithm = quic.PacingAlgorithm

const (
	PacingNative      = quic.PacingNative
	PacingLeakyBucket = quic.PacingLeakyBucket
	PacingScheduled   = quic.PacingScheduled
)

func (q *QUICSettings) pacing() *quic.PacingConfig {
	h := q.handshake()
	if h.Pacing == nil {
		h.Pacing = &quic.PacingConfig{BurstPackets: 1, LumpyPackets: 1, SlowStartGain: 1000, AvoidanceGain: 1000}
	}

	return h.Pacing
}

// Pacing selects the send scheduler independently of congestion control.
func (q *QUICSettings) Pacing(algorithm PacingAlgorithm) *QUICSettings {
	q.pacing().Algorithm = algorithm
	return q
}

// PacingBurstPackets sets initial/idle burst credit in path-sized packets.
func (q *QUICSettings) PacingBurstPackets(packets uint32) *QUICSettings {
	q.pacing().BurstPackets = packets
	return q
}

// PacingGains sets slow-start and avoidance rate multipliers in thousandths.
func (q *QUICSettings) PacingGains(slowStart, avoidance uint32) *QUICSettings {
	q.pacing().SlowStartGain, q.pacing().AvoidanceGain = slowStart, avoidance
	return q
}

// PacingGranularity permits sends whose pacing delay is below this duration.
func (q *QUICSettings) PacingGranularity(granularity time.Duration) *QUICSettings {
	q.pacing().Granularity = granularity
	return q
}

// PacingLumpyBurst limits scheduled bursts by packet count, window fraction
// (thousandths), and minimum estimated bandwidth in bytes per second.
func (q *QUICSettings) PacingLumpyBurst(packets, windowFraction uint32, minBandwidth uint64) *QUICSettings {
	p := q.pacing()
	p.LumpyPackets, p.LumpyWindowFraction, p.LumpyMinBandwidth = packets, windowFraction, minBandwidth
	return q
}

// ProportionalRateReduction enables RFC 6937's send allowance during recovery.
func (q *QUICSettings) ProportionalRateReduction(enabled bool) *QUICSettings {
	q.handshake().ProportionalRateReduction = enabled
	return q
}

// RecoveryBurstPackets permits an immediate bounded send after a new loss event.
func (q *QUICSettings) RecoveryBurstPackets(packets uint32) *QUICSettings {
	q.handshake().RecoveryBurstPackets = packets
	return q
}

// PersistentCongestionThreshold sets the consecutive-loss duration in base PTOs.
// Zero preserves the engine's native behavior; a PTO expiry alone is not a loss.
func (q *QUICSettings) PersistentCongestionThreshold(ptos uint32) *QUICSettings {
	q.handshake().PersistentCongestionThreshold = ptos
	return q
}
