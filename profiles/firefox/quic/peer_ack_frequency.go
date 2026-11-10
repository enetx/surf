package quic

import (
	"time"

	"github.com/enetx/quic-go"
)

// PeerAckFrequency follows Neqo's default ratio of four ACKs per RTT and its
// 25% delay hysteresis. The engine separately handles negotiation and delivery.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/ackrate.rs
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/params.rs
func PeerAckFrequency(info quic.PeerAckFrequencyInfo) (quic.PeerAckFrequency, bool) {
	packets := uint64(2)
	if info.MaxDatagramSize > 0 {
		packets = min(256, max(2, info.CongestionWindow/info.MaxDatagramSize/4))
	}
	// Respect even an unusually large peer minimum without invoking Neqo's
	// invalid clamp(minimum, 50ms) range. Normal browser peers stay below 50ms.
	delay := max(info.PeerMinAckDelay, min(50*time.Millisecond, max(0, info.SmoothedRTT/4)))
	delay = delay.Truncate(time.Microsecond)
	target := quic.PeerAckFrequency{AckElicitingThreshold: packets, MaxAckDelay: delay}
	currentUS, targetUS := info.Current.MaxAckDelay/time.Microsecond, delay/time.Microsecond
	delta := targetUS / 4
	update := info.Current.AckElicitingThreshold != packets || info.Current.IgnoreOrder ||
		targetUS+delta < currentUS || targetUS > currentUS+delta
	return target, update
}
