package android

import (
	"github.com/enetx/http/http2"
	"github.com/enetx/surf/profiles"
)

// ConfigureH2 applies Firefox android HTTP/2 settings.
func ConfigureH2(h profiles.H2Config) {
	h.InitialStreamID(3).
		HeaderTableSize(65536).
		EnablePush(0).
		InitialWindowSize(131072).
		MaxFrameSize(16384).
		ConnectionFlow(12517377).
		PriorityParam(http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    41,
		})
}
