// Package profiles defines the shared variant contract used by browser profile packages
// (profiles/chrome, profiles/firefox, ...) and consumed by the top-level surf package.
//
// Each browser's variants.go assembles its desktop, Android and iOS profiles.
// Each browser's common/headers.go owns its request-header defaults, identity,
// scenarios and wire order. Platform compatibility.go files retain public
// adapters; platform packages also own TLS, HTTP/2 and HTTP/3 settings.
// boundary.go supplies browser form boundaries.
// Each browser's quic/ directory owns config.go, client_hello.go and
// transport_parameters.go for its verified QUIC engine; variants select its use.
//
// A Variant is the self-contained description of one browser and form-factor combination:
// TLS ClientHello, HTTP/2 + HTTP/3 SETTINGS, header set, User-Agent / sec-ch-ua data per OS.
// The surf.Impersonate dispatcher selects a browser/platform Variant, applies its
// static fields, and runs ConfigureH2/ConfigureH3/ConfigureQUIC against fluent
// adapters — without the profile package importing surf.
package profiles

import (
	"context"
	"net"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/tlsquic"
	"github.com/enetx/quic-go/transportparams"
	"github.com/enetx/surf/pkg/tlscache"
	utls "github.com/enetx/utls"
)

// OSKey identifies the impersonated operating system. Surf's Impersonate stores it directly
// (no separate ImpersonateOS enum). Profile packages use it as a lookup key for UA / Platform.
type OSKey int

// SessionCacheConfig is the concrete fluent configuration used by session
// profiles. Surf creates independent cache state after applying overrides.
type SessionCacheConfig = tlscache.Builder

const (
	Windows OSKey = iota
	MacOS
	Linux
	Android
	IOS
)

// IsMobile reports whether the OS is a mobile form factor (Android or iOS).
func (k OSKey) IsMobile() bool { return k == Android || k == IOS }

// Mobile returns the value of the sec-ch-ua-mobile header: "?1" for mobile OS, "?0" otherwise.
func (k OSKey) Mobile() g.String {
	if k.IsMobile() {
		return "?1"
	}

	return "?0"
}

// H2Config is the fluent contract used by profile.ConfigureH2 callbacks. It mirrors the
// methods on surf.HTTP2Settings, the surf package provides an adapter that satisfies it.
type H2Config interface {
	HTTP1RequiredCache(int) H2Config
	StreamReceiveWindow(uint32) H2Config
	ReceiveWindowUpdatePolicy(func(http2.ReceiveWindowUpdateInfo) bool) H2Config
	HeaderTableSize(uint32) H2Config
	MaxEncoderHeaderTableSize(uint32) H2Config
	EnablePush(uint32) H2Config
	MaxConcurrentStreams(uint32) H2Config
	InitialWindowSize(uint32) H2Config
	MaxFrameSize(uint32) H2Config
	MaxHeaderListSize(uint32) H2Config
	NoRFC7540Priorities(uint32) H2Config
	ConnectionFlow(uint32) H2Config
	InitialStreamID(uint32) H2Config
	PriorityParam(http2.PriorityParam) H2Config
	PriorityFrames([]http2.PriorityFrame) H2Config
	HpackPolicy(func(string, string) http2.HPACKRepresentation) H2Config
	HpackIndexingLimit(func(uint32) uint32) H2Config
	HpackHuffman(http2.HPACKHuffmanMode) H2Config
	HpackDeduplicateTableSizeUpdates(bool) H2Config
	HpackNameReferencePolicy(http2.HPACKNameReferencePolicy) H2Config
	HpackRepresentation(string, http2.HPACKRepresentation) H2Config
	HpackDefaultRepresentation(http2.HPACKRepresentation) H2Config
	HeaderPriority(func(http2.PriorityRequest) http2.PriorityParam) H2Config
	ChainStreamDependencies(bool) H2Config
}

// H3Config is the fluent contract used by profile.ConfigureH3 callbacks. It mirrors the
// methods on surf.HTTP3Settings, the surf package provides an adapter that satisfies it.
type H3Config interface {
	// OnResponseHeaders observes valid response headers; an error aborts the request.
	OnResponseHeaders(func(*http.Request, *http.Response) error) H3Config
	Discovery(bool) H3Config
	HTTPSRecordsWait(func(time.Duration) time.Duration) H3Config
	AlternativeServiceBackoff(func(uint32) time.Duration) H3Config
	ExpireFailedAlternatives(bool) H3Config
	ConnectionRacingPolicy(ConnectionRacingPolicy) H3Config
	CoalesceInitialSettings(bool) H3Config
	CoalesceRequestHeaders(bool) H3Config
	EarlyData(bool) H3Config
	// EarlyDataRestart resets rejected HTTP/3 state on the same QUIC connection.
	EarlyDataRestart(bool) H3Config
	EarlyDataBackup(bool) H3Config
	RequestBodyBufferSize(int) H3Config
	RequestBodyBufferSizePolicy(func(int64) int) H3Config
	RequestBodyFirstReadSizePolicy(func(http3.RequestBodyReadInfo) int) H3Config
	MaxDataFrameSize(int) H3Config
	AltUsed(bool) H3Config
	StreamPriority(int8, bool) H3Config
	QpackMaxTableCapacity(uint64) H3Config
	MaxFieldSectionSize(uint64) H3Config
	QpackBlockedStreams(uint64) H3Config
	QpackStreamOrder(...http3.QPACKStreamType) H3Config
	QpackEagerStreamTypes(bool) H3Config
	QpackEncoderTableCapacity(uint64) H3Config
	QpackEncoderCapacityTiming(http3.QPACKCapacityTiming) H3Config
	QpackSplitCookies(bool) H3Config
	QpackNeverIndex(...string) H3Config
	QpackDynamicTable(bool) H3Config
	QpackHuffman(http3.QPACKHuffmanMode) H3Config
	QpackIndexing(http3.QPACKIndexingMode) H3Config
	QpackIndexingPolicy(func(string, string) bool) H3Config
	// QpackResumptionErrorCode configures the accepted-0-RTT capacity error policy.
	QpackResumptionErrorCode(func(uint64, uint64) http3.ErrCode) H3Config
	QpackDrainingFraction(float64) H3Config
	QpackPostBaseReferences(bool) H3Config
	QpackLiteralInsertNames(bool) H3Config
	QpackStopOnInsertionFailure(bool) H3Config
	QpackMaxTrackedSections(uint64) H3Config
	QpackEncoderZeroCapacity(bool) H3Config
	QpackEncoderCapacityRequiresSetting(bool) H3Config
	PriorityUpdates(bool) H3Config
	CompactPriorityUpdates(bool) H3Config
	ControlGreaseFramesFactory(func() ([]http3.GreaseFrame, error)) H3Config
	RequestGreaseFramesFactory(func(*http.Request) ([]http3.GreaseFrame, error)) H3Config
	EnableConnectProtocol(uint64) H3Config
	SettingsH3Datagram(uint64) H3Config
	H3Datagram(uint64) H3Config
	EnableWebtransport(uint64) H3Config
	Grease() H3Config
	GreaseFactory(func() (uint64, uint64, error)) H3Config
}

// QUICConfig is the fluent contract used by ConfigureQUIC callbacks. Every
// method delegates to surf.QUICSettings, so profiles are examples of the same
// API available to applications. The dispatcher calls Set after configuration.
type QUICConfig interface {
	ResumeVersion(bool) QUICConfig
	// ResumeRTT restores measured ticket RTT with the specified precision; zero disables it.
	ResumeRTT(time.Duration) QUICConfig
	// OnEarlyDataRejected observes TLS 0-RTT rejection on the connection loop.
	OnEarlyDataRejected(func(*quic.Conn)) QUICConfig
	InitialRTT(time.Duration) QUICConfig
	InitialPTOMultiplier(uint32) QUICConfig
	CachedInitialRTT(uint64, time.Duration, time.Duration) QUICConfig
	ECHClientHelloInner(utls.ECHClientHelloInnerFunc) QUICConfig
	AddressFallbackDelay(time.Duration) QUICConfig
	CompatibleVersionNegotiation(bool) QUICConfig
	CongestionControl(quic.CongestionControlAlgorithm) QUICConfig
	SlowStart(quic.SlowStartAlgorithm) QUICConfig
	CongestionControlSegmentSize(uint16) QUICConfig
	CongestionControlConnections(uint32) QUICConfig
	SeparatePacketNumberSpaces(bool) QUICConfig
	PacketNumberSkipping(bool) QUICConfig
	InitialCongestionWindowPackets(uint32) QUICConfig
	MaxCongestionWindowPackets(int64) QUICConfig
	Pacing(quic.PacingAlgorithm) QUICConfig
	PacingBurstPackets(uint32) QUICConfig
	PacingGains(uint32, uint32) QUICConfig
	PacingGranularity(time.Duration) QUICConfig
	PacingLumpyBurst(uint32, uint32, uint64) QUICConfig
	ProportionalRateReduction(bool) QUICConfig
	RecoveryBurstPackets(uint32) QUICConfig
	PersistentCongestionThreshold(uint32) QUICConfig
	PeerAckFrequencyPolicy(quic.PeerAckFrequencyPolicy) QUICConfig
	LegacyAckFrequency(time.Duration) QUICConfig
	InitialPacketSizeFactory(func(net.Addr) (uint16, error)) QUICConfig
	InitialCryptoFrameSplits(int, int) QUICConfig
	InitialPingFrames(int, int) QUICConfig
	InitialCryptoFirstFrameSize(int, int) QUICConfig
	// InitialCryptoLayout selects ordered first-ClientHello ranges and packet groups.
	InitialCryptoLayout(func(quic.InitialCryptoLayoutInfo) [][]quic.CryptoRange) QUICConfig
	// InitialCryptoRecovery enables lost-range and late-ACK tracking for Initial.
	InitialCryptoRecovery(bool) QUICConfig
	// InitialCryptoRecoveryLayout applies the packet policy to lost Initial bytes.
	InitialCryptoRecoveryLayout(func(quic.InitialCryptoLayoutInfo) [][]quic.CryptoRange) QUICConfig
	// InitialCryptoProbePackets selects the Initial PTO preparation batch.
	InitialCryptoProbePackets(uint8) QUICConfig
	// InitialProbeSkipPacketNumber controls the deliberate Initial PTO number gap.
	InitialProbeSkipPacketNumber(bool) QUICConfig
	// InitialCryptoResendOnPeerProbe selects reaction to a peer Initial probe.
	InitialCryptoResendOnPeerProbe(bool) QUICConfig
	// CoalescePTOProbes shares a datagram budget across timed encryption spaces.
	CoalescePTOProbes(bool) QUICConfig
	// InitialACKResetsPTO resets backoff before peer address validation completes.
	InitialACKResetsPTO(bool) QUICConfig
	// StreamDataRecovery acknowledges STREAM ranges across transmission copies.
	StreamDataRecovery(bool) QUICConfig
	// StreamLossRetention selects the lifetime of lost STREAM ACK metadata.
	StreamLossRetention(func(quic.StreamLossInfo) bool) QUICConfig
	// HandshakeCryptoRecovery tracks Handshake CRYPTO ranges and late original PTO ACKs.
	HandshakeCryptoRecovery(bool) QUICConfig
	// HandshakeCryptoResendOnPeerProbe resends unacknowledged Handshake CRYPTO
	// on a peer PING or non-progressing CRYPTO frame.
	HandshakeCryptoResendOnPeerProbe(bool) QUICConfig
	// HandshakeProbePackets sets the Handshake PTO allowance (0..2).
	HandshakeProbePackets(uint8) QUICConfig
	// ApplicationProbePackets sets the 1-RTT PTO allowance (0..2).
	ApplicationProbePackets(uint8) QUICConfig
	// HandshakeProbeSkipPacketNumber controls a deliberate Handshake PTO number gap.
	HandshakeProbeSkipPacketNumber(bool) QUICConfig
	// ApplicationProbeSkipPacketNumber separates the 1-RTT PTO gap from random gaps.
	ApplicationProbeSkipPacketNumber(bool) QUICConfig
	// HandshakeProbeOnlyWithData suppresses empty follow-up Handshake probes.
	HandshakeProbeOnlyWithData(bool) QUICConfig
	// PeerPacketRecoveryPolicy selects responses to missing or retired peer keys.
	PeerPacketRecoveryPolicy(func(quic.PeerPacketInfo) quic.PeerPacketRecovery) QUICConfig
	// EarlyDataResendOnPeerCrypto repeats early data on non-progressing Initial CRYPTO.
	EarlyDataResendOnPeerCrypto(bool) QUICConfig
	// ImmediateACKOnPeerPing selects immediate acknowledgment of a verified
	// 1-RTT PING instead of waiting for the normal ACK threshold.
	ImmediateACKOnPeerPing(bool) QUICConfig
	InitialDestinationConnectionIDLengthFactory(func() (int, error)) QUICConfig
	ReceiveWindowUpdateDivisor(uint32) QUICConfig
	AckOnlyPingThreshold(int) QUICConfig
	AckOnlyMaxDataThreshold(int) QUICConfig
	AckProbePolicy(func(quic.AckProbeInfo) bool) QUICConfig
	PacketNumberLengthPolicy(func(quic.PacketNumberLengthInfo) uint8) QUICConfig
	OmitInitialAckOnHandshake(bool) QUICConfig
	InitialPaddingMode(quic.InitialPaddingMode) QUICConfig
	HandshakeAckBeforeData(bool) QUICConfig
	DisableConnectionIDRotation(bool) QUICConfig
	SortConnectionIDFrames(bool) QUICConfig
	OnApplicationReady(func(*quic.Conn)) QUICConfig
	Versions(...quic.Version) QUICConfig
	HandshakeIdleTimeout(time.Duration) QUICConfig
	MaxIdleTimeout(time.Duration) QUICConfig
	KeepAlivePeriod(time.Duration) QUICConfig
	InitialStreamReceiveWindow(uint64) QUICConfig
	MaxStreamReceiveWindow(uint64) QUICConfig
	InitialConnectionReceiveWindow(uint64) QUICConfig
	MaxConnectionReceiveWindow(uint64) QUICConfig
	AllowConnectionWindowIncrease(func(*quic.Conn, uint64) bool) QUICConfig
	MaxIncomingStreams(int64) QUICConfig
	MaxIncomingUniStreams(int64) QUICConfig
	RequireStreamCreditRelease(bool) QUICConfig
	InitialPacketSize(uint16) QUICConfig
	DisablePathMTUDiscovery(bool) QUICConfig
	EnableDatagrams(bool) QUICConfig
	EnableStreamResetPartialDelivery(bool) QUICConfig
	TokenStore(quic.TokenStore) QUICConfig
	Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace) QUICConfig
	ConnectionIDLength(int) QUICConfig
	ConnectionIDGenerator(quic.ConnectionIDGenerator) QUICConfig
	StreamReceiveWindows(uint64, uint64, uint64) QUICConfig
	ClientHelloSpec(*utls.ClientHelloSpec) QUICConfig
	ClientHelloFactory(func() (utls.ClientHelloSpec, error)) QUICConfig
	TLSClientFactory(tlsquic.NewClient) QUICConfig
	MaxUDPPayloadSize(uint64) QUICConfig
	OmitMaxUDPPayloadSize(bool) QUICConfig
	MaxDatagramFrameSize(uint64) QUICConfig
	MaxAckDelay(time.Duration) QUICConfig
	AckPacketThreshold(uint64) QUICConfig
	AckDecimation(uint64, uint64) QUICConfig
	AckDelayRTTDivisor(uint32) QUICConfig
	MinAckDelay(time.Duration) QUICConfig
	AckReordering(quic.AckReorderingMode) QUICConfig
	AckMissingPacketLimit(uint64) QUICConfig
	AckECN(quic.AckECNMode) QUICConfig
	ResetAckPolicy() QUICConfig
	ActiveConnectionIDLimit(uint64) QUICConfig
	OmitLegacyResetStreamAt(bool) QUICConfig
	InitialDestinationConnectionIDLength(int) QUICConfig
	InitialPacketNumber(uint64) QUICConfig
	InitialPacketNumberFactory(func() (uint64, error)) QUICConfig
	DisableClientHelloScrambling(bool) QUICConfig
	TransportParameterOrder(...uint64) QUICConfig
	TransportParameter(uint64, []byte) QUICConfig
	DisableTransportParameterGrease(bool) QUICConfig
	TransportParametersFactory(func(quic.Version) (*transportparams.Layout, error)) QUICConfig
}

// Variant is a self-contained description of one browser and form-factor combination.
type Variant struct {
	// BuildRequestHeaders describes logical defaults and their ordered positions.
	// Protocol zero prepares values before middleware; actual 1/2/3 prepares the
	// final private attempt after routing and Client Hints. Empty values reserve
	// slots without creating fields. Existing user values and metadata win.
	// Nil selects the legacy BuildHeaders/Headers compatibility path.
	BuildRequestHeaders func(HeaderContext) g.MapOrd[g.String, g.String]
	// HeaderCase supplies exact HTTP/1 field spellings for the final attempt.
	// Nil keeps canonical HTTP/1 names. Explicit HeaderCaseKey always wins.
	HeaderCase func(HeaderContext) []string

	// ClientHints provides available serialized hint values for the selected OS.
	// Nil leaves automatic negotiation disabled. Values are copied at Build.
	ClientHints func(OSKey) g.MapOrd[string, string]
	// ClientHintsOrder retains the earlier hint-order callback for variants
	// without BuildRequestHeaders. New factories receive CriticalCH directly.
	ClientHintsOrder func(*http.Request, bool)
	// ConfigureTCPSessionCache sets defaults for owned HTTP/1 and HTTP/2 TLS
	// caches enabled by Session or SessionCache. Explicit application caches
	// retain their own policy. Nil retains the generic policy.
	ConfigureTCPSessionCache func(*SessionCacheConfig)
	// ConfigureQUICSessionCache sets defaults for owned HTTP/3 TLS caches.
	// User overrides apply last; explicit application caches retain their policy.
	ConfigureQUICSessionCache func(*SessionCacheConfig)
	// ECHClientHelloInner supplies the TCP policy. QUIC uses its fluent profile setter.
	ECHClientHelloInner utls.ECHClientHelloInnerFunc
	// HelloSpec takes precedence over HelloID when non-nil.
	HelloSpec *utls.ClientHelloSpec
	HelloID   utls.ClientHelloID

	// ShuffleExtensions re-shuffles HelloSpec's extension order on every connection, as
	// Chromium does since v110. Firefox keeps a fixed order.
	ShuffleExtensions bool

	// Boundary is the multipart boundary generator for this browser. Same reference for both
	// Desktop and Mobile within one profile package (boundary is a per-browser property).
	Boundary func() g.String

	// ConfigureH2 / ConfigureH3 own the fluent SETTINGS chain as code. The surf dispatcher
	// invokes them with adapters and calls Set() afterwards.
	ConfigureH2 func(H2Config)
	ConfigureH3 func(H3Config)
	// ConfigureQPACK selects stream creation and capacity announcement behavior.
	ConfigureQPACK func(H3Config)
	// ConfigureRequestBody selects request body read sizes.
	ConfigureRequestBody func(H3Config)

	// ConfigureQUIC uses the same individual setters as Builder.QUICSettings.
	// Nil retains Surf's defaults. Each application creates fresh private state.
	ConfigureQUIC func(QUICConfig)

	// BuildHeaders supplies the optional static identity fragment. It remains
	// available to callers and variants using the previous callback contract.
	// BuildRequestHeaders is the complete context-aware declaration.
	BuildHeaders func(OSKey) *g.MapOrd[g.String, g.String]

	// Headers applies the standalone plain-method preset adapter. Runtime
	// preparation uses this callback only when BuildRequestHeaders is nil.
	Headers HeadersApplier

	// ProtocolHeaders is the previous private-attempt callback contract for
	// variants without BuildRequestHeaders. Built-in factories declare their
	// protocol values and positions directly.
	ProtocolHeaders ProtocolHeaders

	// RequestHeaders is the previous request-aware protocol callback for
	// variants without BuildRequestHeaders. Only Header may be changed.
	RequestHeaders func(*http.Request, int)
}
