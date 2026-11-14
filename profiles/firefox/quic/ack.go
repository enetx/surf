package quic

import (
	"github.com/enetx/quic-go"
	"github.com/enetx/surf/profiles"
)

// Neqo's receive default ACKs after tolerance+1 (=2) contiguous ack-eliciting
// packets, retains the first deadline, and ACKs out-of-order arrivals. ackrate.rs
// controls requests to the peer, not this receiver. Its ratio is not decimation.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/tracking.rs
func configureAck(q profiles.QUICConfig) {
	// Firefox drains socket input before asking Neqo for output, so a queued
	// ACK may cover more than its two-packet trigger. Keep receive batching.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/socket/neqo_glue/src/lib.rs
	q.AckFlushOnPacket(false).AckPacketThreshold(2).AckDecimation(0, 0).
		AckDelayRTTDivisor(0).MinAckDelay(0).
		AckReordering(quic.AckReorderingImmediate).AckMissingPacketLimit(0).
		AckECN(quic.AckECNCountOnly)
}
