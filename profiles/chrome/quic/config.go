package quic

import (
	"time"

	"github.com/enetx/surf/profiles/chrome/common"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf/profiles"
)

// ConfigureQUIC applies Chromium's QUIC settings through Surf's fluent API.
// Flow-control limits and empty SCIDs follow Chromium 157's quic_context.cc;
// see tests/testdata/wire/README.md for sources and remaining limitations.
func ConfigureQUIC(q profiles.QUICConfig) {
	// Cached SRTT is advertised only for direct connections; QUICHE clamps
	// its local untrusted estimate, retaining the actual wire value.
	// https://chromium.googlesource.com/chromium/src/+/157.0.8103.51/net/quic/quic_session_pool.cc#2621
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_sent_packet_manager.cc#L134
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_constants.h#L102
	q.CachedInitialRTT(0x3127, 10*time.Millisecond, time.Second)
	// GetProbeTimeoutDelay uses three initial RTTs before any ACK sample.
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_sent_packet_manager.cc#L58
	q.InitialPTOMultiplier(3)
	// QUICHE's external BBR defaults are false. TcpCubicSenderBytes uses
	// kDefaultTCPMSS=1460 and kDefaultNumConnections=2, independently of UDP MTU.
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/common/quiche_feature_flags_list.h
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/common/platform/default/quiche_platform_impl/quiche_flags_impl.cc
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/congestion_control/tcp_cubic_sender_bytes.cc
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_constants.h
	q.CongestionControl(quic.CongestionControlCubicBytes).
		SlowStart(quic.SlowStartHybrid).
		CongestionControlSegmentSize(1460).
		CongestionControlConnections(2).
		PeerAckFrequencyPolicy(nil).
		// quic_max_congestion_window counts fixed accounting segments.
		// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/common/quiche_protocol_flags_list.h
		MaxCongestionWindowPackets(2000).
		InitialCongestionWindowPackets(32)
	// QUICHE scheduled pacing, idle burst, lumpy thresholds, and PRR.
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/congestion_control/pacing_sender.cc
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/congestion_control/prr_sender.cc
	q.Pacing(quic.PacingScheduled).PacingBurstPackets(10).
		PacingGains(2000, 1250).PacingGranularity(time.Millisecond).
		PacingLumpyBurst(2, 250, 150000).ProportionalRateReduction(true).
		RecoveryBurstPackets(0).PersistentCongestionThreshold(0)
	// QuicPacketCreator increments one packet_.packet_number across levels.
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_packet_creator.cc
	q.SeparatePacketNumberSpaces(false).CompatibleVersionNegotiation(false).
		Versions(quic.Version1).
		HandshakeIdleTimeout(10*time.Second).
		MaxIdleTimeout(30*time.Second).
		KeepAlivePeriod(0).
		InitialStreamReceiveWindow(6<<20).
		MaxStreamReceiveWindow(6<<20).
		InitialConnectionReceiveWindow(15<<20).
		MaxConnectionReceiveWindow(15<<20).
		MaxIncomingStreams(100).
		MaxIncomingUniStreams(103).
		InitialPacketSize(1250).
		DisablePathMTUDiscovery(true).
		EnableDatagrams(true).
		ConnectionIDLength(ConnectionIDLength).
		ClientHelloFactory(NewClientHelloSpec).
		ECHClientHelloInner(common.ClientHelloInner).
		TransportParametersFactory(NewTransportParameters).
		MaxUDPPayloadSize(1472).
		MaxDatagramFrameSize(65536).
		MaxAckDelay(25*time.Millisecond).
		ActiveConnectionIDLimit(2).
		InitialDestinationConnectionIDLength(8).
		ReceiveWindowUpdateDivisor(2).
		AckOnlyPingThreshold(-1).
		// OnAckNeedsRetransmittableFrame repeats the current connection window.
		// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_session.cc
		// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_constants.h
		AckOnlyMaxDataThreshold(19).
		OmitInitialAckOnHandshake(true).
		// QUICHE retains peer-issued IDs until retirement or a path change.
		// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_connection_id_manager.cc
		DisableConnectionIDRotation(true).
		// QUICHE's packet-local and multi-packet Chaos Protection ranges.
		// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_chaos_protector.cc
		// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/quic_packet_creator.cc
		InitialCryptoFrameSplits(2, 10).
		InitialPingFrames(2, 10).
		InitialCryptoFirstFrameSize(55, 86).
		InitialPacketNumber(1).
		PacketNumberLengthPolicy(PacketNumberLength).
		DisableClientHelloScrambling(true)
	configureAck(q)
}

// ConnectionIDLength is the browser's local source connection ID length.
const ConnectionIDLength = 0
