package quic

import "github.com/enetx/quic-go"

// StreamLossRetention selects whether a lost STREAM packet can still supply ACKs.
// Neqo removes lost packet metadata after the current backed-off PTO period.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/recovery/mod.rs
func StreamLossRetention(info quic.StreamLossInfo) bool {
	return info.TimeSinceLoss < info.ProbeTimeout
}
