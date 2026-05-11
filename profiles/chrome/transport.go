package chrome

import (
	"github.com/enetx/http2"
	"github.com/enetx/surf/profiles"
)

// configureH2Desktop applies the desktop Chrome 145 HTTP/2 SETTINGS chain.
func configureH2Desktop(h profiles.H2Config) {
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

// configureH2Mobile applies the placeholder mobile Chrome 145 HTTP/2 SETTINGS chain.
// On the day real Chrome Android 145 H/2 settings are observed, replace this body.
func configureH2Mobile(h profiles.H2Config) {
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

// configureH3Desktop applies the desktop Chrome 145 HTTP/3 SETTINGS chain.
func configureH3Desktop(h profiles.H3Config) {
	h.QpackMaxTableCapacity(65536).
		MaxFieldSectionSize(262144).
		QpackBlockedStreams(100).
		SettingsH3Datagram(1).
		Grease()
}

// configureH3Mobile applies the placeholder mobile Chrome 145 HTTP/3 SETTINGS chain.
// On the day real Chrome Android 145 H/3 settings are observed, replace this body.
func configureH3Mobile(h profiles.H3Config) {
	h.QpackMaxTableCapacity(65536).
		MaxFieldSectionSize(262144).
		QpackBlockedStreams(100).
		SettingsH3Datagram(1).
		Grease()
}
