package desktop

import (
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox/common"
)

// ConfigureH3 applies Firefox desktop HTTP/3 settings.
func ConfigureH3(h profiles.H3Config) {
	h.AltUsed(true).
		ConnectionRacingPolicy(common.ConnectionRacing).
		QpackMaxTableCapacity(65536).
		QpackBlockedStreams(20).
		EnableWebtransport(0).
		H3Datagram(1).
		SettingsH3Datagram(1).
		EnableConnectProtocol(1)
}
