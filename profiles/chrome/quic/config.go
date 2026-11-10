package quic

import (
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf/profiles"
)

// ConfigureQUIC applies Chromium's QUIC settings through Surf's fluent API.
// Flow-control limits and empty SCIDs follow Chromium 156's quic_context.cc;
// see tests/testdata/wire/README.md for sources and remaining limitations.
func ConfigureQUIC(q profiles.QUICConfig) {
	q.Versions(quic.Version1).
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
		TransportParametersFactory(NewTransportParameters).
		MaxUDPPayloadSize(1472).
		MaxDatagramFrameSize(65536).
		MaxAckDelay(25*time.Millisecond).
		ActiveConnectionIDLimit(2).
		InitialDestinationConnectionIDLength(8).
		ReceiveWindowUpdateDivisor(2).
		AckOnlyPingThreshold(-1).
		// OnAckNeedsRetransmittableFrame repeats the current connection window.
		// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_session.cc
		// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_constants.h
		AckOnlyMaxDataThreshold(19).
		OmitInitialAckOnHandshake(true).
		// QUICHE retains peer-issued IDs until retirement or a path change.
		// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_connection_id_manager.cc
		DisableConnectionIDRotation(true).
		// QUICHE's packet-local and multi-packet Chaos Protection ranges.
		// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_chaos_protector.cc
		// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_packet_creator.cc
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
