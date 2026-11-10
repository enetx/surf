package desktop

import (
	"github.com/enetx/surf/profiles"
	chromequic "github.com/enetx/surf/profiles/chrome/quic"
)

// ConfigureH3 applies Chrome desktop HTTP/3 settings.
func ConfigureH3(h profiles.H3Config) {
	h.QpackMaxTableCapacity(65536).
		MaxFieldSectionSize(262144).
		QpackBlockedStreams(100).
		SettingsH3Datagram(1).
		GreaseFactory(chromequic.NewSettingsGrease)
}
