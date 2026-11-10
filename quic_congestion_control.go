package surf

import "github.com/enetx/quic-go"

type CongestionControlAlgorithm = quic.CongestionControlAlgorithm
type SlowStartAlgorithm = quic.SlowStartAlgorithm

const (
	CongestionControlNative     = quic.CongestionControlNative
	CongestionControlReno       = quic.CongestionControlReno
	CongestionControlCubic      = quic.CongestionControlCubic
	CongestionControlCubicBytes = quic.CongestionControlCubicBytes
	SlowStartNative             = quic.SlowStartNative
	SlowStartClassic            = quic.SlowStartClassic
	SlowStartHybrid             = quic.SlowStartHybrid
)

// CongestionControl selects Reno, RFC 9438 CUBIC, or fixed-point byte-mode
// CUBIC. Native restores the engine default. Pacing and loss detection are separate.
func (q *QUICSettings) CongestionControl(algorithm CongestionControlAlgorithm) *QUICSettings {
	q.handshake().CongestionControl = algorithm
	return q
}

// SlowStart selects classic acknowledged-byte growth or original HyStart.
// Native retains the engine's HyStart; Hybrid is not HyStart++.
func (q *QUICSettings) SlowStart(algorithm SlowStartAlgorithm) *QUICSettings {
	q.handshake().SlowStart = algorithm
	return q
}

// CongestionControlSegmentSize fixes the accounting segment independently of
// UDP packet size. Zero follows the path MTU; explicit values are 1200..65527.
func (q *QUICSettings) CongestionControlSegmentSize(bytes uint16) *QUICSettings {
	q.handshake().CongestionControlSegmentSize = bytes
	return q
}

// CongestionControlConnections sets the number of emulated byte-mode CUBIC
// connections (1..16). Zero means one; other algorithms allow only zero or one.
func (q *QUICSettings) CongestionControlConnections(count uint32) *QUICSettings {
	q.handshake().CongestionControlConnections = count
	return q
}
