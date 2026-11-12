package desktop

import (
	"math"

	"github.com/enetx/http/http2"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox/common"
)

// ConfigureH2 applies Firefox desktop HTTP/2 settings.
// Http2Compressor::HuffmanAppend always applies Huffman. ProcessHeader scans
// static names before dynamic names and keeps the last non-exact candidate.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2Compression.cpp
func ConfigureH2(h profiles.H2Config) {
	// Http2Compressor::SetMaxBufferSize accepts the peer's SETTINGS value;
	// let the native encoder use its full supported capacity range.
	h.MaxEncoderHeaderTableSize(math.MaxInt32).
		ReceiveWindowUpdatePolicy(common.ReceiveWindowUpdate).
		// AdjustInitialWindow raises client-pulled streams above the push allowance.
		// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2StreamBase.cpp
		StreamReceiveWindow(12 << 20).
		HpackPolicy(common.HpackPolicy).
		HpackIndexingLimit(common.HpackIndexingLimit).
		HpackHuffman(http2.HPACKHuffmanAlways).
		HpackNameReferencePolicy(http2.HPACKNameReferenceLast).
		InitialStreamID(3).
		HeaderTableSize(65536).
		EnablePush(0).
		InitialWindowSize(131072).
		MaxFrameSize(16384).
		ConnectionFlow(12517377).
		PriorityParam(common.HeaderPriority(http2.PriorityRequest{})).
		HeaderPriority(common.HeaderPriority)
}
