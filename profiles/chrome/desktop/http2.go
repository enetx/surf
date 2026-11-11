package desktop

import (
	"math"

	"github.com/enetx/http/http2"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
)

// ConfigureH2 applies Chrome desktop HTTP/2 settings.
// Open-stream dependencies follow Chromium's HTTP/2 priority model.
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/spdy/http2_priority_dependencies.cc
func ConfigureH2(h profiles.H2Config) {
	// Quiche accepts the peer's table size. Use the native engine's largest
	// supported bound instead of its 4096-byte default encoder limit.
	// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/http2/hpack/hpack_encoder.cc
	h.MaxEncoderHeaderTableSize(math.MaxInt32).
		ReceiveWindowUpdatePolicy(common.ReceiveWindowUpdate).
		HpackPolicy(common.HpackPolicy).
		HpackNameReferencePolicy(http2.HPACKNameReferenceFirst).
		HpackDeduplicateTableSizeUpdates(true).
		ChainStreamDependencies(true).
		HeaderTableSize(65536).
		EnablePush(0).
		InitialWindowSize(6291456).
		MaxHeaderListSize(262144).
		ConnectionFlow(15663105).
		PriorityParam(http2.PriorityParam{
			StreamDep: 0,
			Exclusive: true,
			Weight:    255,
		})
}
