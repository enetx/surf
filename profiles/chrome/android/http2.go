package android

import (
	"math"

	"github.com/enetx/http/http2"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
)

// ConfigureH2 applies Chrome Android HTTP/2 settings.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/spdy/http2_priority_dependencies.cc
func ConfigureH2(h profiles.H2Config) {
	// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/http2/hpack/hpack_encoder.cc
	h.MaxEncoderHeaderTableSize(math.MaxInt32).
		HTTP1RequiredCache(common.HTTP1RequiredCacheCapacity).
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
		}).
		HeaderPriority(common.HeaderPriority)
}
