package desktop

import "github.com/enetx/surf/profiles"

// ConfigureH3 applies Firefox desktop HTTP/3 settings.
func ConfigureH3(h profiles.H3Config) {
	h.AltUsed(true).
		QpackMaxTableCapacity(65536).
		QpackBlockedStreams(20).
		EnableWebtransport(0).
		H3Datagram(1).
		SettingsH3Datagram(1).
		EnableConnectProtocol(1)
}
