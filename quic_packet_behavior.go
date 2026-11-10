package surf

import (
	"net"

	"github.com/enetx/quic-go"
)

// InitialPacketSizeFactory selects the initial UDP payload size for the actual
// remote address. It must return promptly and be concurrency safe. Nil restores
// the fixed size. Results must fit the QUIC engine's supported packet sizes.
func (q *QUICSettings) InitialPacketSizeFactory(factory func(net.Addr) (uint16, error)) *QUICSettings {
	q.handshake().NewInitialPacketSize = factory
	return q
}

// ReceiveWindowUpdateDivisor refreshes stream/connection credit after more than
// 1/divisor of its window is consumed. Zero retains native behavior; one is invalid.
func (q *QUICSettings) ReceiveWindowUpdateDivisor(divisor uint32) *QUICSettings {
	q.handshake().ReceiveWindowUpdateDivisor = divisor
	return q
}

// AckOnlyPingThreshold controls extra PINGs after consecutive ACK-only packets.
// Zero retains native behavior; -1 disables these PINGs, preserving PTO probes.
func (q *QUICSettings) AckOnlyPingThreshold(threshold int) *QUICSettings {
	q.handshake().AckOnlyPingThreshold = threshold
	q.handshake().AckOnlyMaxDataThreshold = 0
	q.handshake().AckProbePolicy = nil

	return q
}

// AckOnlyMaxDataThreshold solicits acknowledgment by repeating current MAX_DATA
// after a run of ACK-only packets. It grants no extra credit and replaces the
// periodic PING policy. Zero clears this policy; PTO probes remain independent.
func (q *QUICSettings) AckOnlyMaxDataThreshold(threshold int) *QUICSettings {
	h := q.handshake()
	h.AckOnlyMaxDataThreshold = threshold
	h.AckProbePolicy = nil

	if threshold > 0 {
		h.AckOnlyPingThreshold = -1
	}

	return q
}

// OmitInitialAckOnHandshake omits an ACK-only Initial when Handshake data is ready.
func (q *QUICSettings) OmitInitialAckOnHandshake(omit bool) *QUICSettings {
	q.handshake().OmitInitialAckOnHandshake = omit
	return q
}

func (q *QUICSettings) initialPacketProtection() *quic.InitialPacketProtection {
	h := q.handshake()

	if h.InitialPacketProtection == nil {
		h.InitialPacketProtection = &quic.InitialPacketProtection{}
	}

	return h.InitialPacketProtection
}

// InitialCryptoFrameSplits sets an inclusive range of random split attempts per
// padded client Initial. Available padding bounds the actual number of splits.
func (q *QUICSettings) InitialCryptoFrameSplits(min, max int) *QUICSettings {
	p := q.initialPacketProtection()
	p.MinCryptoSplits, p.MaxCryptoSplits = min, max

	return q
}

// InitialPingFrames sets the inclusive random PING count in protected Initials.
// Both endpoints must be in 0..64. This does not affect 1-RTT ACK-only PINGs.
func (q *QUICSettings) InitialPingFrames(min, max int) *QUICSettings {
	p := q.initialPacketProtection()
	p.MinPingFrames, p.MaxPingFrames = min, max

	return q
}

// InitialCryptoFirstFrameSize selects a prefix size for cross-packet protection.
// A first packet carries that prefix and trailing ClientHello bytes, with the
// middle in following packets. Zero disables this layout. Bounds are 0..16384.
func (q *QUICSettings) InitialCryptoFirstFrameSize(min, max int) *QUICSettings {
	p := q.initialPacketProtection()
	p.MinFirstFrameSize, p.MaxFirstFrameSize = min, max

	return q
}

// ResetInitialPacketProtection restores native packet framing and scrambling.
// DisableClientHelloScrambling retains its independently configured value.
func (q *QUICSettings) ResetInitialPacketProtection() *QUICSettings {
	q.handshake().InitialPacketProtection = nil
	return q
}

// PacketNumberLengthPolicy chooses 1..4 encoded bytes per packet from live
// recovery state. Zero or invalid results retain native behavior; the transport
// increases results that cannot safely represent the unacknowledged range.
func (q *QUICSettings) PacketNumberLengthPolicy(policy func(quic.PacketNumberLengthInfo) uint8) *QUICSettings {
	q.handshake().PacketNumberLengthPolicy = policy
	return q
}

// AckProbePolicy replaces periodic ACK-only probes with a decision based on
// recovery state. It runs in the send loop and must not block or reenter the
// connection. Nil disables this callback. PTO recovery remains independent.
func (q *QUICSettings) AckProbePolicy(policy func(quic.AckProbeInfo) bool) *QUICSettings {
	h := q.handshake()
	h.AckProbePolicy = policy

	if policy != nil {
		h.AckOnlyPingThreshold = -1
		h.AckOnlyMaxDataThreshold = 0
	}

	return q
}

// DisableConnectionIDRotation keeps the active ID on an unchanged path.
// Peer retirement and connection migration continue to replace IDs as needed.
func (q *QUICSettings) DisableConnectionIDRotation(disable bool) *QUICSettings {
	q.handshake().DisableConnectionIDRotation = disable
	return q
}

// OnApplicationReady stages application data after verified TLS and peer
// parameters, before the next flight. It must not block or call CloseWithError;
// use OpenUniStream and TryWriteAll rather than blocking stream writes.
func (q *QUICSettings) OnApplicationReady(callback func(*quic.Conn)) *QUICSettings {
	q.handshake().OnApplicationReady = callback
	return q
}

// InitialPaddingMode selects encrypted PADDING or a zero-filled datagram tail
// after coalesced packets. Header-protection sample padding remains encrypted.
func (q *QUICSettings) InitialPaddingMode(mode quic.InitialPaddingMode) *QUICSettings {
	q.handshake().InitialPaddingMode = mode
	return q
}

// HandshakeAckBeforeData separates queued handshake ACKs from the first local
// Handshake CRYPTO flight without adding a timer or changing TLS verification.
func (q *QUICSettings) HandshakeAckBeforeData(enabled bool) *QUICSettings {
	q.handshake().HandshakeAckBeforeData = enabled
	return q
}

const (
	InitialPaddingPacket   = quic.InitialPaddingPacket
	InitialPaddingDatagram = quic.InitialPaddingDatagram
)

// SortConnectionIDFrames sends queued NEW_CONNECTION_ID frames in ascending
// sequence order. Other control-frame types keep their native relative positions.
func (q *QUICSettings) SortConnectionIDFrames(enabled bool) *QUICSettings {
	q.handshake().SortConnectionIDFrames = enabled
	return q
}
