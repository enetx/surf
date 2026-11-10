package android

import (
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox/common"
)

// ConfigureH3 applies Firefox android HTTP/3 settings.
func ConfigureH3(h profiles.H3Config) {
	h.QpackMaxTableCapacity(65536).
		ConnectionRacingPolicy(common.ConnectionRacing).
		QpackBlockedStreams(20).
		EnableWebtransport(0).
		H3Datagram(1).
		SettingsH3Datagram(1).
		EnableConnectProtocol(1)
}
