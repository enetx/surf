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
		HandshakeIdleTimeout(10 * time.Second).
		MaxIdleTimeout(30 * time.Second).
		KeepAlivePeriod(0).
		InitialStreamReceiveWindow(6 << 20).
		MaxStreamReceiveWindow(6 << 20).
		InitialConnectionReceiveWindow(15 << 20).
		MaxConnectionReceiveWindow(15 << 20).
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
		MaxAckDelay(25 * time.Millisecond).
		ActiveConnectionIDLimit(2).
		InitialPacketNumber(1).
		DisableClientHelloScrambling(true)
}

// ConnectionIDLength is the browser's local source connection ID length.
const ConnectionIDLength = 0
