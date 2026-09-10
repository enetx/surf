package chrome

import "github.com/enetx/surf/profiles"

// Desktop is the Chrome 152 desktop variant - current production fingerprint.
var Desktop = profiles.Variant{
	HelloSpec:         &HelloChrome_152,
	ShuffleExtensions: true,
	Boundary:          Boundary,
	ConfigureH2:       configureH2Desktop,
	ConfigureH3:       configureH3Desktop,
	BuildHeaders:      buildHeadersDesktop,
	Headers:           DesktopApplier,
}

// Mobile is a placeholder Chrome 152 mobile variant. On the day real Chrome Android 152 bytes
// are observed, replace HelloChrome_152_Mobile, configureH2Mobile, configureH3Mobile and
// buildHeadersMobile bodies — the variant fields below stay as-is.
var Mobile = profiles.Variant{
	HelloSpec:         &HelloChrome_152_Mobile,
	ShuffleExtensions: true,
	Boundary:          Boundary,
	ConfigureH2:       configureH2Mobile,
	ConfigureH3:       configureH3Mobile,
	BuildHeaders:      buildHeadersMobile,
	Headers:           MobileApplier,
}
