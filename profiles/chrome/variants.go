package chrome

import (
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/android"
	"github.com/enetx/surf/profiles/chrome/desktop"
	"github.com/enetx/surf/profiles/chrome/ios"
)

// Desktop is the current Chrome 156 desktop variant.
var Desktop = profiles.Variant{
	HelloSpec:         &HelloChrome_156,
	ShuffleExtensions: true,
	Boundary:          Boundary,
	ConfigureH2:       desktop.ConfigureH2,
	ConfigureH3:       desktop.ConfigureH3,
	BuildHeaders:      desktop.BuildHeaders,
	Headers:           DesktopApplier,
}

// Mobile is the current Chrome 156 Android variant.
var Mobile = profiles.Variant{
	HelloSpec:         &HelloChrome_156_Mobile,
	ShuffleExtensions: true,
	Boundary:          Boundary,
	ConfigureH2:       android.ConfigureH2,
	ConfigureH3:       android.ConfigureH3,
	BuildHeaders:      android.BuildHeaders,
	Headers:           MobileApplier,
}

// IOS is the current Chrome 157 iOS variant.
var IOS = profiles.Variant{
	HelloSpec:    &HelloChrome_157_IOS,
	HelloID:      ios.HelloID,
	Boundary:     Boundary,
	ConfigureH2:  ios.ConfigureH2,
	ConfigureH3:  ios.ConfigureH3,
	BuildHeaders: ios.BuildHeaders,
	Headers:      IOSApplier,
}
