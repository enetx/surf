package quic

import "github.com/enetx/quic-go"

// AckProbe follows Neqo's outstanding-packet thresholds and strict PTO deadline.
// It is considered only while sending an otherwise ACK-only packet.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/third_party/rust/neqo-transport/src/recovery/mod.rs
func AckProbe(info quic.AckProbeInfo) bool {
	if !info.HasLastAckEliciting || info.PTO <= 0 || info.OutstandingPackets < 16 {
		return false
	}

	if info.OutstandingPackets >= 200 {
		return info.SinceLastAckEliciting > info.PTO
	}

	// Divide the elapsed interval to avoid overflowing a user-supplied duration.
	return info.SinceLastAckEliciting > info.PTO && info.SinceLastAckEliciting-info.PTO > info.PTO
}
