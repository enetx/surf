package surf

import (
	"bytes"
	"context"
	"net"
	"slices"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/tlsquic"
	"github.com/enetx/quic-go/transportparams"
	quictransport "github.com/enetx/surf/internal/quic"
	utls "github.com/enetx/utls"
)

// QUICSettings configures the HTTP/3 transport through Surf's fluent API.
// Each setter changes only its own option, retaining the selected browser profile.
// Set returns the main Builder; ForceHTTP3 selects use of this transport.
type QUICSettings struct {
	http3 *HTTP3Settings
}

// InitialCryptoLayoutInfo supplies the ClientHello boundaries and live Initial
// packet budgets to an InitialCryptoLayout policy.
type InitialCryptoLayoutInfo = quic.InitialCryptoLayoutInfo

// PeerPacketInfo describes a routed packet whose keys are unavailable.
type PeerPacketInfo = quic.PeerPacketInfo

// PeerPacketRecovery selects transport responses without accepting the packet.
type PeerPacketRecovery = quic.PeerPacketRecovery

// CryptoRange selects a byte range in the first ClientHello's CRYPTO stream.
type CryptoRange = quic.CryptoRange

const (
	InitialPaddingPacket   = quic.InitialPaddingPacket
	InitialPaddingDatagram = quic.InitialPaddingDatagram
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

type (
	PeerAckFrequency       = quic.PeerAckFrequency
	PeerAckFrequencyInfo   = quic.PeerAckFrequencyInfo
	PeerAckFrequencyPolicy = quic.PeerAckFrequencyPolicy
)

type (
	CongestionControlAlgorithm = quic.CongestionControlAlgorithm
	SlowStartAlgorithm         = quic.SlowStartAlgorithm
)

const (
	CongestionControlNative     = quic.CongestionControlNative
	CongestionControlReno       = quic.CongestionControlReno
	CongestionControlCubic      = quic.CongestionControlCubic
	CongestionControlCubicBytes = quic.CongestionControlCubicBytes
	SlowStartNative             = quic.SlowStartNative
	SlowStartClassic            = quic.SlowStartClassic
	SlowStartHybrid             = quic.SlowStartHybrid
)

type PacingAlgorithm = quic.PacingAlgorithm

const (
	PacingNative      = quic.PacingNative
	PacingLeakyBucket = quic.PacingLeakyBucket
	PacingScheduled   = quic.PacingScheduled
)

// Set applies the accumulated QUIC settings and returns the main Builder.
func (q *QUICSettings) Set() *Builder { return q.http3.Set() }

// ResumeVersion chooses the first QUIC version from an available session ticket
// previously stored by this client for the origin. Expired, evicted, unmarked
// and disabled-version tickets retain the configured first version. It does not
// reorder the caller's configuration. The Firefox profile enables this policy.
func (q *QUICSettings) ResumeVersion(enabled bool) *QUICSettings {
	q.http3.options.ResumeVersion = enabled
	return q
}

// ResumeRTT restores a measured RTT from the selected live TLS ticket, rounded
// down to the supplied precision. Zero disables restoration. Firefox uses whole
// milliseconds; this local recovery estimate does not advertise a parameter.
// The supported range is zero through one minute; Build rejects other values.
func (q *QUICSettings) ResumeRTT(precision time.Duration) *QUICSettings {
	q.http3.options.ResumeRTTGranularity = precision
	return q
}

// OnEarlyDataRejected observes a TLS rejection of QUIC 0-RTT. It runs on the
// connection loop and must return promptly without reentering the connection.
// Nil removes the application observer; owned-cache rejection handling remains.
func (q *QUICSettings) OnEarlyDataRejected(callback func(*quic.Conn)) *QUICSettings {
	q.handshake().OnEarlyDataRejected = callback
	return q
}

// InitialRTT sets the local recovery estimate before the first measurement.
// Zero uses the native default. No transport parameter is advertised by it.
func (q *QUICSettings) InitialRTT(estimate time.Duration) *QUICSettings {
	q.handshake().InitialRTT = estimate
	return q
}

// InitialPTOMultiplier controls probe timing before the first RTT measurement.
// Zero uses the native factor; supported explicit factors are 1..16.
func (q *QUICSettings) InitialPTOMultiplier(factor uint32) *QUICSettings {
	q.handshake().InitialPTOMultiplier = factor
	return q
}

// CachedInitialRTT learns measured RTT from this client's preceding direct
// connection to each origin. It owns parameter and encodes the measured RTT in
// microseconds; an empty history omits it. Local recovery uses the same estimate
// clamped to minimum..maximum. Proxy connections do not share this history.
// Parameter zero disables it. Bounds must be positive and ordered when enabled.
func (q *QUICSettings) CachedInitialRTT(parameter uint64, minimum, maximum time.Duration) *QUICSettings {
	q.http3.options.CachedRTTParameter = parameter
	q.http3.options.MinimumInitialRTT = minimum
	q.http3.options.MaximumInitialRTT = maximum
	return q
}

func (q *QUICSettings) config() *quic.Config {
	if q.http3.options.QUICConfig == nil {
		q.http3.options.QUICConfig = quictransport.DefaultConfig()
	}
	return q.http3.options.QUICConfig
}

// Versions sets the allowed QUIC versions. The input slice is copied.
// An empty list selects the versions supported by quic-go.
func (q *QUICSettings) Versions(versions ...quic.Version) *QUICSettings {
	q.config().Versions = slices.Clone(versions)
	return q
}

// HandshakeIdleTimeout sets the idle timeout during connection establishment.
// Zero selects quic-go's default.
func (q *QUICSettings) HandshakeIdleTimeout(timeout time.Duration) *QUICSettings {
	q.config().HandshakeIdleTimeout = timeout
	return q
}

// MaxIdleTimeout sets the maximum idle time after the handshake.
// Zero selects quic-go's default.
func (q *QUICSettings) MaxIdleTimeout(timeout time.Duration) *QUICSettings {
	q.config().MaxIdleTimeout = timeout
	return q
}

// KeepAlivePeriod sets the interval between keep-alive packets. Zero disables them.
func (q *QUICSettings) KeepAlivePeriod(period time.Duration) *QUICSettings {
	q.config().KeepAlivePeriod = period
	return q
}

// InitialStreamReceiveWindow sets the common initial stream receive window.
// It replaces any per-direction StreamReceiveWindows override.
func (q *QUICSettings) InitialStreamReceiveWindow(size uint64) *QUICSettings {
	q.config().InitialStreamReceiveWindow = size
	q.handshake().StreamReceiveWindows = nil
	return q
}

// MaxStreamReceiveWindow sets the receive window limit for each stream.
func (q *QUICSettings) MaxStreamReceiveWindow(size uint64) *QUICSettings {
	q.config().MaxStreamReceiveWindow = size
	return q
}

// InitialConnectionReceiveWindow sets the initial connection receive window.
func (q *QUICSettings) InitialConnectionReceiveWindow(size uint64) *QUICSettings {
	q.config().InitialConnectionReceiveWindow = size
	return q
}

// MaxConnectionReceiveWindow sets the connection receive window limit.
func (q *QUICSettings) MaxConnectionReceiveWindow(size uint64) *QUICSettings {
	q.config().MaxConnectionReceiveWindow = size
	return q
}

// AllowConnectionWindowIncrease decides whether automatic receive window growth
// is permitted. The callback must not call connection or stream methods.
func (q *QUICSettings) AllowConnectionWindowIncrease(allow func(*quic.Conn, uint64) bool) *QUICSettings {
	q.config().AllowConnectionWindowIncrease = allow
	return q
}

// MaxIncomingStreams limits concurrent peer-initiated bidirectional streams.
// Zero selects quic-go's default; a negative value disallows them.
func (q *QUICSettings) MaxIncomingStreams(limit int64) *QUICSettings {
	q.config().MaxIncomingStreams = limit
	return q
}

// MaxIncomingUniStreams limits concurrent peer-initiated unidirectional streams.
// Zero selects quic-go's default; a negative value disallows them.
func (q *QUICSettings) MaxIncomingUniStreams(limit int64) *QUICSettings {
	q.config().MaxIncomingUniStreams = limit
	return q
}

// RequireStreamCreditRelease keeps completed peer streams counted until their
// credit is explicitly released. This is for applications managing incoming streams.
func (q *QUICSettings) RequireStreamCreditRelease(required bool) *QUICSettings {
	q.config().RequireStreamCreditRelease = required
	return q
}

// InitialPacketSize sets the initial packet size in bytes (at least 1200).
// Zero selects quic-go's default.
func (q *QUICSettings) InitialPacketSize(size uint16) *QUICSettings {
	q.config().InitialPacketSize = size
	q.handshake().NewInitialPacketSize = nil

	return q
}

// DisablePathMTUDiscovery controls whether QUIC probes for a larger path MTU.
func (q *QUICSettings) DisablePathMTUDiscovery(disabled bool) *QUICSettings {
	q.config().DisablePathMTUDiscovery = disabled
	return q
}

// EnableDatagrams configures both QUIC and HTTP/3 datagram support.
func (q *QUICSettings) EnableDatagrams(enabled bool) *QUICSettings {
	q.config().EnableDatagrams = enabled
	q.http3.EnableDatagrams(enabled)

	if !enabled {
		q.handshake().MaxDatagramFrameSize = 0
	}

	return q
}

// EnableStreamResetPartialDelivery controls reliable stream resets.
func (q *QUICSettings) EnableStreamResetPartialDelivery(enabled bool) *QUICSettings {
	q.config().EnableStreamResetPartialDelivery = enabled
	return q
}

// TokenStore sets the shared store of address validation tokens. Nil disables it.
func (q *QUICSettings) TokenStore(store quic.TokenStore) *QUICSettings {
	q.config().TokenStore = store
	return q
}

// Tracer supplies a trace recorder for each new QUIC connection.
func (q *QUICSettings) Tracer(tracer func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace) *QUICSettings {
	q.config().Tracer = tracer
	return q
}

// ConnectionIDLength sets the local connection ID length, from 0 through 20.
// Zero uses a dedicated UDP socket for each connection.
func (q *QUICSettings) ConnectionIDLength(length int) *QUICSettings {
	q.http3.ConnectionIDLength(length)
	return q
}

// ConnectionIDGenerator sets a custom generator, taking precedence over length.
func (q *QUICSettings) ConnectionIDGenerator(generator quic.ConnectionIDGenerator) *QUICSettings {
	q.http3.ConnectionIDGenerator(generator)
	return q
}

// CompatibleVersionNegotiation enables authenticated v1/v2 switching within a
// handshake (RFC 9368/9369). Versions lists the permitted versions; a custom
// transport-parameter layout can select their preference and GREASE ordering.
// Firefox enables this mechanism by default. Native clients keep it disabled.
func (q *QUICSettings) CompatibleVersionNegotiation(enabled bool) *QUICSettings {
	q.handshake().CompatibleVersionNegotiation = enabled
	return q
}

func (q *QUICSettings) handshake() *quic.ClientHandshake {
	if q.http3.options.ClientHandshake == nil {
		q.http3.options.ClientHandshake = q.config().ClientHandshake.Clone()

		if q.http3.options.ClientHandshake == nil {
			q.http3.options.ClientHandshake = &quic.ClientHandshake{}
		}
	}

	return q.http3.options.ClientHandshake
}

// StreamReceiveWindows sets initial bidirectional-local, bidirectional-remote
// and unidirectional receive windows. Zero explicitly advertises zero credit.
func (q *QUICSettings) StreamReceiveWindows(bidiLocal, bidiRemote, uni uint64) *QUICSettings {
	q.handshake().StreamReceiveWindows = &quic.StreamReceiveWindows{
		BidiLocal: bidiLocal, BidiRemote: bidiRemote, Uni: uni,
	}

	return q
}

// ClientHelloSpec snapshots an explicit QUIC TLS template. Nil restores standard TLS.
func (q *QUICSettings) ClientHelloSpec(spec *utls.ClientHelloSpec) *QUICSettings {
	q.http3.ClientHelloSpec(spec)
	return q
}

// ClientHelloFactory supplies a fresh QUIC TLS template per connection attempt.
// It may run concurrently; templates must not share mutable extensions.
func (q *QUICSettings) ClientHelloFactory(factory func() (utls.ClientHelloSpec, error)) *QUICSettings {
	q.http3.ClientHelloFactory(factory)
	return q
}

// TLSClientFactory sets a custom QUIC TLS engine. Configure either this factory
// or ClientHelloSpec/ClientHelloFactory; using both returns an error.
func (q *QUICSettings) TLSClientFactory(factory tlsquic.NewClient) *QUICSettings {
	q.handshake().NewTLSClient = factory
	return q
}

// TLSClientFactoryWrapper decorates the native or browser TLS factory for each
// connection. The factory receives a private TLS config with destination and ALPN
// set. The wrapper must preserve session events and must not perform network I/O.
// HTTP/3 adds its per-ticket SETTINGS bookkeeping outside this wrapper.
// Nil removes the application wrapper without changing the selected TLS engine.
func (q *QUICSettings) TLSClientFactoryWrapper(
	wrapper func(*quic.Conn, tlsquic.NewClient) tlsquic.NewClient,
) *QUICSettings {
	q.handshake().WrapTLSClient = wrapper
	return q
}

// MaxUDPPayloadSize sets the advertised UDP payload limit and actual receive size.
// It also enables advertising this parameter after OmitMaxUDPPayloadSize(true).
func (q *QUICSettings) MaxUDPPayloadSize(size uint64) *QUICSettings {
	h := q.handshake()
	h.MaxUDPPayloadSize = size
	h.OmitMaxUDPPayloadSize = false

	return q
}

// OmitMaxUDPPayloadSize omits the parameter and provisions the protocol default
// receive size when enabled. False advertises the current payload limit.
func (q *QUICSettings) OmitMaxUDPPayloadSize(omit bool) *QUICSettings {
	h := q.handshake()

	h.OmitMaxUDPPayloadSize = omit

	if omit {
		h.MaxUDPPayloadSize = quic.MaxUDPReceivePacketSize
	}

	return q
}

// MaxDatagramFrameSize sets the advertised QUIC datagram limit.
// Datagram support must also be enabled. Zero selects quic-go's default.
func (q *QUICSettings) MaxDatagramFrameSize(size uint64) *QUICSettings {
	q.handshake().MaxDatagramFrameSize = size
	return q
}

// MaxAckDelay sets the acknowledgment scheduling bound in whole milliseconds.
// Zero selects quic-go's default.
func (q *QUICSettings) MaxAckDelay(delay time.Duration) *QUICSettings {
	q.handshake().MaxAckDelay = delay
	return q
}

// ActiveConnectionIDLimit sets the receive-side connection ID limit (at least 2).
// Zero selects quic-go's default.
func (q *QUICSettings) ActiveConnectionIDLimit(limit uint64) *QUICSettings {
	q.handshake().ActiveConnectionIDLimit = limit
	return q
}

// OmitLegacyResetStreamAt controls advertising the legacy reliable-reset parameter.
func (q *QUICSettings) OmitLegacyResetStreamAt(omit bool) *QUICSettings {
	q.handshake().OmitLegacyResetStreamAt = omit
	return q
}

// InitialDestinationConnectionIDLength sets the Initial destination ID length.
// Nonzero lengths must be 8 through 20; zero selects quic-go's default.
func (q *QUICSettings) InitialDestinationConnectionIDLength(length int) *QUICSettings {
	q.handshake().InitialDestinationConnectionIDLength = length
	q.handshake().NewInitialDestinationConnectionIDLength = nil

	return q
}

// InitialDestinationConnectionIDLengthFactory chooses a fresh 8..20 byte length
// per connection. Nil restores the fixed length. The factory may run concurrently.
func (q *QUICSettings) InitialDestinationConnectionIDLengthFactory(factory func() (int, error)) *QUICSettings {
	q.handshake().NewInitialDestinationConnectionIDLength = factory
	return q
}

// InitialPacketNumber sets a fixed initial packet number and clears any factory.
func (q *QUICSettings) InitialPacketNumber(number uint64) *QUICSettings {
	h := q.handshake()

	h.InitialPacketNumber = number
	h.NewInitialPacketNumber = nil

	return q
}

// InitialPacketNumberFactory supplies a fresh initial number per connection.
// Nil restores the fixed number. The factory may run concurrently.
func (q *QUICSettings) InitialPacketNumberFactory(factory func() (uint64, error)) *QUICSettings {
	q.handshake().NewInitialPacketNumber = factory
	return q
}

// DisableClientHelloScrambling controls SNI/ECH CRYPTO fragmentation.
func (q *QUICSettings) DisableClientHelloScrambling(disabled bool) *QUICSettings {
	q.handshake().DisableClientHelloScrambling = disabled
	return q
}

// TransportParameterOrder sets preferred parameter order. Unlisted parameters
// follow in their original order. Use transportparams.Grease for native GREASE.
// The order is copied and also applies to layouts generated by a browser factory.
func (q *QUICSettings) TransportParameterOrder(ids ...uint64) *QUICSettings {
	order := slices.Clone(ids)
	quictransport.EditTransportParameters(q.handshake(), func(layout *transportparams.Layout) {
		layout.Order = slices.Clone(order)
	})

	return q
}

// TransportParameter adds or replaces an extension parameter with wire-encoded
// bytes. The value is copied. Engine-owned parameters must use their own setters.
// Advertising a parameter does not implement an extension protocol.
func (q *QUICSettings) TransportParameter(id uint64, value []byte) *QUICSettings {
	value = bytes.Clone(value)
	quictransport.EditTransportParameters(q.handshake(), func(layout *transportparams.Layout) {
		parameter := transportparams.Parameter{ID: id, Value: bytes.Clone(value)}

		for i := range layout.Additional {
			if layout.Additional[i].ID == id {
				layout.Additional[i] = parameter

				return
			}
		}

		layout.Additional = append(layout.Additional, parameter)
	})

	return q
}

// DisableTransportParameterGrease controls reserved transport parameters,
// including those supplied by a browser factory. False uses native QUIC GREASE.
func (q *QUICSettings) DisableTransportParameterGrease(disabled bool) *QUICSettings {
	quictransport.EditTransportParameters(q.handshake(), func(layout *transportparams.Layout) {
		layout.DisableGrease = disabled
		layout.Additional = slices.DeleteFunc(layout.Additional, func(p transportparams.Parameter) bool {
			return quictransport.IsGreaseParameter(p.ID)
		})

		order := layout.Order[:0]
		seen := false

		for _, id := range layout.Order {
			if id == transportparams.Grease || quictransport.IsGreaseParameter(id) {
				if disabled || seen {
					continue
				}

				id, seen = transportparams.Grease, true
			}

			order = append(order, id)
		}

		layout.Order = order
	})

	return q
}

// TransportParametersFactory supplies a layout per handshake attempt, replacing
// any previous factory and its edits. Later layout setters amend its result.
// The factory may run concurrently. Nil restores the static layout.
func (q *QUICSettings) TransportParametersFactory(
	factory func(quic.Version) (*transportparams.Layout, error),
) *QUICSettings {
	q.handshake().NewTransportParameters = factory
	return q
}

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

// InitialCryptoLayout chooses ordered ranges of the first ClientHello for each
// Initial packet from its SNI/ECH positions, unsent ranges and live packet budget.
// Each result must cover Remaining exactly once; invalid layouts fail before
// sending. The engine sends the first group and reconsiders the remaining bytes
// with the next packet's actual budget. Nil retains native preparation.
// The policy must support concurrent calls and return promptly. Later Initial
// data, including a HelloRetryRequest response, keeps normal stream ordering.
func (q *QUICSettings) InitialCryptoLayout(policy func(InitialCryptoLayoutInfo) [][]CryptoRange) *QUICSettings {
	q.handshake().InitialCryptoLayout = policy
	return q
}

// InitialCryptoRecovery tracks lost Initial bytes independently of their old
// frame boundaries and retires them when a packet copy is acknowledged. Browser
// profiles enable this automatically. Disabling clears its layout and probe batch.
func (q *QUICSettings) InitialCryptoRecovery(enabled bool) *QUICSettings {
	h := q.handshake()
	h.InitialCryptoRecovery = enabled

	if !enabled {
		h.InitialCryptoRecoveryLayout = nil
		h.InitialCryptoProbePackets = 0
		h.InitialCryptoResendOnPeerProbe = false
	}

	return q
}

// InitialCryptoRecoveryLayout selects ordered lost ranges for each Initial
// packet's live budget. Offsets remain absolute across HelloRetryRequest; Length
// can include later Initial messages. A non-nil policy enables byte-range recovery.
// Nil restores sequential lost ranges while retaining the current recovery mode.
func (q *QUICSettings) InitialCryptoRecoveryLayout(policy func(InitialCryptoLayoutInfo) [][]CryptoRange) *QUICSettings {
	h := q.handshake()
	h.InitialCryptoRecoveryLayout = policy

	if policy != nil {
		h.InitialCryptoRecovery = true
	}

	return q
}

// InitialCryptoProbePackets sets the Initial PTO allowance and preparation batch.
// Zero keeps the native allowance and a one-packet batch; valid counts are 0..2.
// A nonzero count enables byte-range recovery and original-packet ACK tracking.
func (q *QUICSettings) InitialCryptoProbePackets(count uint8) *QUICSettings {
	h := q.handshake()
	h.InitialCryptoProbePackets = count

	if count != 0 {
		h.InitialCryptoRecovery = true
	}

	return q
}

// InitialProbeSkipPacketNumber skips one Initial number when PTO fires to elicit
// an immediate ACK. This is independent of Application Data PacketNumberSkipping.
func (q *QUICSettings) InitialProbeSkipPacketNumber(enabled bool) *QUICSettings {
	q.handshake().InitialProbeSkipPacketNumber = enabled
	return q
}

// InitialCryptoResendOnPeerProbe resends sent, unacknowledged Initial bytes on
// PING or CRYPTO input that delivers no new TLS bytes. Enabling also selects
// byte-range recovery. Browser profiles configure their own policy.
func (q *QUICSettings) InitialCryptoResendOnPeerProbe(enabled bool) *QUICSettings {
	h := q.handshake()
	h.InitialCryptoResendOnPeerProbe = enabled

	if enabled {
		h.InitialCryptoRecovery = true
	}

	return q
}

// CoalescePTOProbes shares one datagram budget across eligible encryption spaces.
// It retains crypto PTO baselines and suppresses empty crypto follow-up probes;
// queued data can still be sent in every space. Firefox enables this policy.
func (q *QUICSettings) CoalescePTOProbes(enabled bool) *QUICSettings {
	q.handshake().CoalescePTOProbes = enabled
	return q
}

// InitialACKResetsPTO resets probe-timeout backoff on a new Initial ACK before
// peer address validation completes. Firefox selects this recovery policy.
func (q *QUICSettings) InitialACKResetsPTO(enabled bool) *QUICSettings {
	q.handshake().InitialACKResetsPTO = enabled
	return q
}

// StreamDataRecovery acknowledges STREAM byte ranges across all transmitted
// copies, including late originals and split retransmissions. Browser profiles
// enable it automatically; disabling retains the native frame recovery path.
func (q *QUICSettings) StreamDataRecovery(enabled bool) *QUICSettings {
	q.handshake().StreamDataRecovery = enabled
	return q
}

// StreamLossRetention selects the lifetime of lost STREAM packet ACK metadata.
// The callback receives transport measurements and must not block or reenter
// QUIC. Nil retains useful metadata up to the engine's packet tracking limit.
func (q *QUICSettings) StreamLossRetention(policy func(quic.StreamLossInfo) bool) *QUICSettings {
	q.handshake().StreamLossRetention = policy
	return q
}

// HandshakeCryptoRecovery tracks Handshake CRYPTO ranges and late original PTO ACKs.
// Disabling also removes its peer-probe retransmission policy.
func (q *QUICSettings) HandshakeCryptoRecovery(enabled bool) *QUICSettings {
	h := q.handshake()
	h.HandshakeCryptoRecovery = enabled
	if !enabled {
		h.HandshakeCryptoResendOnPeerProbe = false
	}

	return q
}

// HandshakeCryptoResendOnPeerProbe resends unacknowledged Handshake CRYPTO
// on PING or non-progressing CRYPTO. Enabling also selects Handshake recovery.
func (q *QUICSettings) HandshakeCryptoResendOnPeerProbe(enabled bool) *QUICSettings {
	h := q.handshake()
	h.HandshakeCryptoResendOnPeerProbe = enabled
	if enabled {
		h.HandshakeCryptoRecovery = true
	}

	return q
}

// HandshakeProbePackets sets the Handshake PTO allowance (0..2).
// Zero preserves the native allowance; the selected profile supplies its default.
func (q *QUICSettings) HandshakeProbePackets(count uint8) *QUICSettings {
	q.handshake().HandshakeProbePackets = count
	return q
}

// ApplicationProbePackets sets the 1-RTT PTO allowance (0..2).
// Zero preserves the native allowance. It does not change random number skipping.
func (q *QUICSettings) ApplicationProbePackets(count uint8) *QUICSettings {
	q.handshake().ApplicationProbePackets = count
	return q
}

// HandshakeProbeSkipPacketNumber controls a deliberate Handshake PTO number gap.
func (q *QUICSettings) HandshakeProbeSkipPacketNumber(enabled bool) *QUICSettings {
	q.handshake().HandshakeProbeSkipPacketNumber = enabled
	return q
}

// ApplicationProbeSkipPacketNumber controls the 1-RTT PTO gap independently of
// random PacketNumberSkipping. It overrides that setting for PTO only. Browser
// profiles select their explicit policy; native configs retain the legacy coupling.
func (q *QUICSettings) ApplicationProbeSkipPacketNumber(enabled bool) *QUICSettings {
	q.handshake().ApplicationProbeSkipPacketNumber = &enabled
	return q
}

// HandshakeProbeOnlyWithData suppresses empty follow-up Handshake probes.
// The first probe can still send PING; queued CRYPTO uses the full allowance.
func (q *QUICSettings) HandshakeProbeOnlyWithData(enabled bool) *QUICSettings {
	q.handshake().HandshakeProbeOnlyWithData = enabled
	return q
}

// PeerPacketRecoveryPolicy selects responses to missing or retired peer keys.
// Authentication failures never invoke it. Nil restores native behavior.
func (q *QUICSettings) PeerPacketRecoveryPolicy(
	policy func(quic.PeerPacketInfo) quic.PeerPacketRecovery,
) *QUICSettings {
	q.handshake().PeerPacketRecoveryPolicy = policy
	return q
}

// EarlyDataResendOnPeerCrypto repeats outstanding 0-RTT recovery tokens when
// authenticated Initial CRYPTO makes no TLS progress. The first Application ACK
// ends this mechanism. PING alone never repeats early STREAM data.
func (q *QUICSettings) EarlyDataResendOnPeerCrypto(enabled bool) *QUICSettings {
	q.handshake().EarlyDataResendOnPeerCrypto = enabled
	return q
}

// ImmediateACKOnPeerPing selects immediate acknowledgment of a verified 1-RTT
// PING. Other application packets retain the configured ACK policy.
func (q *QUICSettings) ImmediateACKOnPeerPing(enabled bool) *QUICSettings {
	q.handshake().ImmediateACKOnPeerPing = enabled
	return q
}

// ResetInitialPacketProtection clears random Initial splits, PINGs and prefix
// sizing. Explicit InitialCryptoLayout and DisableClientHelloScrambling retain
// their independently configured values.
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

// SortConnectionIDFrames sends queued NEW_CONNECTION_ID frames in ascending
// sequence order. Other control-frame types keep their native relative positions.
func (q *QUICSettings) SortConnectionIDFrames(enabled bool) *QUICSettings {
	q.handshake().SortConnectionIDFrames = enabled
	return q
}

// SeparatePacketNumberSpaces starts Handshake and Application Data at zero,
// independently of Initial. 0-RTT and 1-RTT remain one space.
func (q *QUICSettings) SeparatePacketNumberSpaces(enabled bool) *QUICSettings {
	q.handshake().SeparatePacketNumberSpaces = enabled
	return q
}

// PacketNumberSkipping controls random Application Data gaps. It also controls
// PTO gaps unless ApplicationProbeSkipPacketNumber explicitly overrides them.
// Peer ACK validation remains enabled.
func (q *QUICSettings) PacketNumberSkipping(enabled bool) *QUICSettings {
	q.handshake().DisablePacketNumberSkipping = !enabled
	return q
}

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

// LegacyAckFrequency enables the legacy single-byte ignore_order extension and
// advertises its minimum requested ACK delay. Zero disables it. The delay must
// be a whole number of microseconds no larger than MaxAckDelay. Local ACK policy
// remains in effect until a valid peer update arrives; this is receive support.
func (q *QUICSettings) LegacyAckFrequency(minimum time.Duration) *QUICSettings {
	q.handshake().LegacyAckFrequencyMinDelay = minimum
	return q
}

// PeerAckFrequencyPolicy selects outgoing legacy ACK_FREQUENCY requests after
// the peer advertises support. The callback receives live window, MTU and RTT
// state plus the last acknowledged request. Nil disables sending; local receive
// policy and its LegacyAckFrequency advertisement remain independent.
func (q *QUICSettings) PeerAckFrequencyPolicy(policy PeerAckFrequencyPolicy) *QUICSettings {
	q.handshake().PeerAckFrequencyPolicy = policy
	return q
}

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

// MaxCongestionWindowPackets caps the send window in accounting segments. Zero
// restores the engine default; -1 removes this packet-count ceiling.
func (q *QUICSettings) MaxCongestionWindowPackets(packets int64) *QUICSettings {
	q.handshake().MaxCongestionWindowPackets = packets
	return q
}

// InitialCongestionWindowPackets sets the initial send window in datagram-sized
// packets (path MTU unless CongestionControlSegmentSize is fixed). Zero restores the engine default; supported explicit values are 2..10000.
func (q *QUICSettings) InitialCongestionWindowPackets(packets uint32) *QUICSettings {
	q.handshake().InitialCongestionWindowPackets = packets
	return q
}

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

// AddressFallbackDelay enables staggered QUIC attempts to resolved addresses.
// Zero preserves serial address attempts. Positive values require 1-RTT.
func (q *QUICSettings) AddressFallbackDelay(delay time.Duration) *QUICSettings {
	q.http3.options.AddressFallbackDelay = delay
	return q
}

// ECHClientHelloInner supplies the real QUIC ECH inner ClientHello policy.
func (q *QUICSettings) ECHClientHelloInner(policy utls.ECHClientHelloInnerFunc) *QUICSettings {
	q.http3.ECHClientHelloInner(policy)
	return q
}
