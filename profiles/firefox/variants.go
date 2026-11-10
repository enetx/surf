package firefox

import (
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox/android"
	"github.com/enetx/surf/profiles/firefox/desktop"
	"github.com/enetx/surf/profiles/firefox/ios"
	"github.com/enetx/surf/profiles/firefox/quic"
)

// Desktop is the current Firefox 160 desktop variant.
var Desktop = profiles.Variant{
	ConfigureQUIC:        quic.ConfigureQUIC,
	HelloSpec:            &HelloFirefox_160,
	Boundary:             Boundary,
	ConfigureH2:          desktop.ConfigureH2,
	ConfigureH3:          desktop.ConfigureH3,
	ConfigureQPACK:       quic.ConfigureQPACK,
	ConfigureRequestBody: quic.ConfigureRequestBody,
	BuildHeaders:         desktop.BuildHeaders,
	Headers:              DesktopApplier,
	ProtocolHeaders:      desktop.ProtocolHeaders,
}

// Mobile is the current Firefox 148 Android variant.
// Its existing placeholder fingerprint is kept independently editable.
var Mobile = profiles.Variant{
	HelloID:      HelloFirefox_148_Mobile,
	Boundary:     Boundary,
	ConfigureH2:  android.ConfigureH2,
	ConfigureH3:  android.ConfigureH3,
	BuildHeaders: android.BuildHeaders,
	Headers:      MobileApplier,
}

// IOS is the current Firefox 148 iOS variant.
// Its existing placeholder fingerprint is kept independently editable.
var IOS = profiles.Variant{
	HelloID:      ios.HelloID,
	Boundary:     Boundary,
	ConfigureH2:  ios.ConfigureH2,
	ConfigureH3:  ios.ConfigureH3,
	BuildHeaders: ios.BuildHeaders,
	Headers:      IOSApplier,
}
