// Package profiles defines the shared variant contract used by browser profile packages
// (profiles/chrome, profiles/firefox, ...) and consumed by the top-level surf package.
//
// Each browser's variants.go assembles its desktop, Android and iOS profiles.
// Platform subpackages own tls.go, headers.go, http2.go and http3.go. Shared
// User-Agent values live in common/; boundary.go supplies browser form boundaries.
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
	utls "github.com/refraction-networking/utls"
)

// OSKey identifies the impersonated operating system. Surf's Impersonate stores it directly
// (no separate ImpersonateOS enum). Profile packages use it as a lookup key for UA / Platform.
type OSKey int

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
	Discovery(bool) H3Config
	AlternativeServiceBackoff(func(uint32) time.Duration) H3Config
	ExpireFailedAlternatives(bool) H3Config
	ConnectionRacingPolicy(ConnectionRacingPolicy) H3Config
	CoalesceInitialSettings(bool) H3Config
	CoalesceRequestHeaders(bool) H3Config
	EarlyData(bool) H3Config
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

	// BuildHeaders constructs the full ordered header map for one request — pseudo-headers,
	// Accept-Encoding, Accept-Language, authorization/cookie/origin/referer placeholders,
	// sec-ch-ua-* (Chromium only), User-Agent. Profile packages provide one BuildHeaders per
	// Variant so each browser and form-factor has its own single point of substitution for the
	// entire header set (set, values, and order are all browser-specific).
	BuildHeaders func(OSKey) *g.MapOrd[g.String, g.String]

	// Headers inserts per-request defaults and orders fields for this platform.
	// Each variant supplies its own pipeline; the request path uses this callback
	// without importing a concrete browser package.
	Headers HeadersApplier

	// ProtocolHeaders supplies protocol-specific defaults after routing. It
	// operates on a private attempt, so fallback does not inherit those defaults.
	ProtocolHeaders ProtocolHeaders

	// RequestHeaders adjusts protocol defaults using the request method. Only
	// Header may be changed; the request and header map are private to the attempt.
	RequestHeaders func(*http.Request, int)
}
