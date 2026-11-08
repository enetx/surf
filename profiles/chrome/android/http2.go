package android

import (
	"github.com/enetx/http/http2"
	"github.com/enetx/surf/profiles"
)

// ConfigureH2 applies Chrome Android HTTP/2 settings.
func ConfigureH2(h profiles.H2Config) {
	h.HeaderTableSize(65536).
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
