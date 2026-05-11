package firefox

import "github.com/enetx/surf/profiles"

// Desktop is the Firefox 148 desktop variant — current production fingerprint.
var Desktop = profiles.Variant{
	HelloID:      HelloFirefox_148,
	Boundary:     Boundary,
	ConfigureH2:  configureH2Desktop,
	ConfigureH3:  configureH3Desktop,
	BuildHeaders: buildHeadersDesktop,
	Headers:      DesktopApplier,
}

// Mobile is a placeholder Firefox 148 mobile variant. On the day real Firefox Android 148 bytes
// are observed, replace HelloFirefox_148_Mobile, configureH2Mobile, configureH3Mobile and
// buildHeadersMobile bodies — the variant fields below stay as-is.
var Mobile = profiles.Variant{
	HelloID:      HelloFirefox_148_Mobile,
	Boundary:     Boundary,
	ConfigureH2:  configureH2Mobile,
	ConfigureH3:  configureH3Mobile,
	BuildHeaders: buildHeadersMobile,
	Headers:      MobileApplier,
}
