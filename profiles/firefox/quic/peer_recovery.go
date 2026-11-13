package quic

import (
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlog"
)

// PeerRecovery follows Neqo's pre-handshake missing-key hints. It does not
// authenticate packets or override certificate verification. Neqo's two saved
// datagram stores each hold four entries; either full store stops Initial hints.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/saved.rs
func PeerRecovery(info quic.PeerPacketInfo) quic.PeerPacketRecovery {
	if info.HandshakeComplete {
		return quic.PeerPacketRecovery{}
	}

	if info.KeysDropped {
		return quic.PeerPacketRecovery{ProbeHandshake: info.PacketType == qlog.PacketTypeInitial}
	}

	resend := !info.ReceivedFirstPacket &&
		(info.PacketType == qlog.PacketTypeHandshake || info.PacketType == qlog.PacketType1RTT) &&
		info.BufferedHandshakePackets < 4 && info.BufferedApplicationPackets < 4

	return quic.PeerPacketRecovery{ResendInitialCrypto: resend, ResendEarlyData: resend}
}
