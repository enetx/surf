package firefox

import (
	"github.com/enetx/http2"
	"github.com/enetx/surf/profiles"
)

// configureH2Desktop applies the desktop Firefox 148 HTTP/2 SETTINGS chain.
func configureH2Desktop(h profiles.H2Config) {
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

// configureH2Mobile applies the placeholder mobile Firefox 148 HTTP/2 SETTINGS chain.
// On the day real Firefox Android 148 H/2 settings are observed, replace this body.
func configureH2Mobile(h profiles.H2Config) {
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

// configureH3Desktop applies the desktop Firefox 148 HTTP/3 SETTINGS chain.
func configureH3Desktop(h profiles.H3Config) {
	h.QpackMaxTableCapacity(65536).
		QpackBlockedStreams(20).
		EnableWebtransport(0).
		H3Datagram(1).
		SettingsH3Datagram(1).
		EnableConnectProtocol(1)
}

// configureH3Mobile applies the placeholder mobile Firefox 148 HTTP/3 SETTINGS chain.
// On the day real Firefox Android 148 H/3 settings are observed, replace this body.
func configureH3Mobile(h profiles.H3Config) {
	h.QpackMaxTableCapacity(65536).
		QpackBlockedStreams(20).
		EnableWebtransport(0).
		H3Datagram(1).
		SettingsH3Datagram(1).
		EnableConnectProtocol(1)
}
