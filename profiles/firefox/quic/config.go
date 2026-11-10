package quic

import (
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf/profiles"
)

// ConfigureQUIC applies Firefox 160's QUIC settings through Surf's fluent API.
// Per-direction stream credit and connection windows are browser policy;
// the QUIC fork supplies only the controls.
func ConfigureQUIC(q profiles.QUICConfig) {
	// Neqo's 10*MTU initial window applies to this profile's sub-1472-byte MTU.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/cc/classic_cc.rs
	// Firefox selects CUBIC and classic slow start by default (cc_algorithm=1,
	// slow_start_algorithm=0). Keep this policy in the profile, not the engine.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/modules/libpref/init/StaticPrefList.yaml
	q.CongestionControl(quic.CongestionControlCubic).
		SlowStart(quic.SlowStartClassic).
		CongestionControlSegmentSize(0).
		CongestionControlConnections(1).
		InitialCongestionWindowPackets(10)
	q.Versions(quic.Version1).
		HandshakeIdleTimeout(10*time.Second).
		MaxIdleTimeout(30*time.Second).
		KeepAlivePeriod(0).
		InitialStreamReceiveWindow(1<<20).
		MaxStreamReceiveWindow(12<<20).
		InitialConnectionReceiveWindow(24<<20).
		MaxConnectionReceiveWindow(24<<20).
		MaxIncomingStreams(100).
		MaxIncomingUniStreams(100).
		DisablePathMTUDiscovery(true).
		EnableDatagrams(true).
		EnableStreamResetPartialDelivery(true).
		ConnectionIDLength(ConnectionIDLength).
		ClientHelloFactory(NewClientHelloSpec).
		StreamReceiveWindows(12<<20, 1<<20, 1<<20).
		TransportParametersFactory(NewTransportParameters).
		InitialPacketNumberFactory(NewInitialPacketNumber).
		OmitMaxUDPPayloadSize(true).
		MaxDatagramFrameSize(65535).
		MaxAckDelay(20 * time.Millisecond).
		// Neqo's min_ack_delay and legacy ACK_FREQUENCY receiver.
		// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs
		LegacyAckFrequency(time.Millisecond).
		PeerAckFrequencyPolicy(PeerAckFrequency).
		ActiveConnectionIDLimit(8).
		OmitLegacyResetStreamAt(true).
		DisableClientHelloScrambling(true)
	// Neqo keeps the active path's ID until Retire Prior To or migration.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/path.rs
	// Neqo output_dgram_on_path retires Initial keys on the first Handshake
	// send; pad_initial adds a zero tail after coalesced encrypted packets.
	// AuthenticationPending allows its ACK flight to precede client Finished.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs
	q.InitialPaddingMode(quic.InitialPaddingDatagram).
		HandshakeAckBeforeData(true).
		DisableConnectionIDRotation(true).
		// Neqo ConnectionIdManager::write_frames assigns increasing sequence numbers.
		// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/cid.rs
		SortConnectionIDFrames(true).
		ReceiveWindowUpdateDivisor(4).
		AckProbePolicy(AckProbe).
		PacketNumberLengthPolicy(PacketNumberLength).
		InitialPacketSizeFactory(NewInitialPacketSize).
		InitialDestinationConnectionIDLengthFactory(NewInitialDestinationConnectionIDLength)
	configureAck(q)
}

// ConnectionIDLength is the browser's local source connection ID length.
const ConnectionIDLength = 3
