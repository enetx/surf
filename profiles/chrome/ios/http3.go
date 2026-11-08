package ios

import "github.com/enetx/surf/profiles"

// ConfigureH3 applies Chrome iOS HTTP/3 settings.
func ConfigureH3(h profiles.H3Config) {
	h.QpackMaxTableCapacity(16383).
		QpackBlockedStreams(100).
		Grease()
}
