package quic

import (
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf/profiles"
)

// ConfigureQUIC applies Firefox 159's QUIC settings through Surf's fluent API.
// Per-direction stream credit and connection windows are browser policy;
// the QUIC fork supplies only the controls.
func ConfigureQUIC(q profiles.QUICConfig) {
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
		ActiveConnectionIDLimit(8).
		OmitLegacyResetStreamAt(true).
		DisableClientHelloScrambling(true)
	configureAck(q)
}

// ConnectionIDLength is the browser's local source connection ID length.
const ConnectionIDLength = 3
