package ios

import "github.com/enetx/surf/profiles"

// ConfigureH2 applies Chrome iOS HTTP/2 settings.
func ConfigureH2(h profiles.H2Config) {
	h.EnablePush(0).
		MaxConcurrentStreams(100).
		InitialWindowSize(2097152).
		NoRFC7540Priorities(1).
		ConnectionFlow(10420225)
}
