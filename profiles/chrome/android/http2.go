package android

import (
	"math"

	"github.com/enetx/http/http2"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
)

// ConfigureH2 applies Chrome Android HTTP/2 settings.
// https://github.com/chromium/chromium/blob/156.0.8078.79/net/spdy/http2_priority_dependencies.cc
func ConfigureH2(h profiles.H2Config) {
	// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/http2/hpack/hpack_encoder.cc
	h.MaxEncoderHeaderTableSize(math.MaxInt32).
		HpackPolicy(common.HpackPolicy).
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
