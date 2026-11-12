package chrome

import (
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/android"
	"github.com/enetx/surf/profiles/chrome/common"
	"github.com/enetx/surf/profiles/chrome/desktop"
	"github.com/enetx/surf/profiles/chrome/ios"
	"github.com/enetx/surf/profiles/chrome/quic"
)

// Desktop is the current Chrome 158 desktop variant.
var Desktop = profiles.Variant{
	ConfigureTCPSessionCache:  common.ConfigureTCPSessionCache,
	ConfigureQUICSessionCache: quic.ConfigureSessionCache,
	ECHClientHelloInner:       common.ClientHelloInner,
	ConfigureQUIC:             quic.ConfigureQUIC,
	HelloSpec:                 &HelloChrome_158,
	ShuffleExtensions:         true,
	Boundary:                  Boundary,
	ConfigureH2:               desktop.ConfigureH2,
	ConfigureH3:               desktop.ConfigureH3,
	ConfigureQPACK:            quic.ConfigureQPACK,
	ConfigureRequestBody:      quic.ConfigureRequestBody,
	BuildHeaders:              desktop.BuildHeaders,
	Headers:                   DesktopApplier,
	RequestHeaders:            common.RequestHeaders,
}

// Mobile is the current Chrome 158 Android variant.
var Mobile = profiles.Variant{
	ConfigureTCPSessionCache:  common.ConfigureTCPSessionCache,
	ConfigureQUICSessionCache: quic.ConfigureSessionCache,
	ECHClientHelloInner:       common.ClientHelloInner,
	ConfigureQUIC:             quic.ConfigureQUIC,
	HelloSpec:                 &HelloChrome_158_Mobile,
	ShuffleExtensions:         true,
	Boundary:                  Boundary,
	ConfigureH2:               android.ConfigureH2,
	ConfigureH3:               android.ConfigureH3,
	ConfigureQPACK:            quic.ConfigureQPACK,
	ConfigureRequestBody:      quic.ConfigureRequestBody,
	BuildHeaders:              android.BuildHeaders,
	Headers:                   MobileApplier,
	RequestHeaders:            common.RequestHeaders,
}

// IOS selects Chrome 158 branding over the independently captured WebKit
// shape. A new iOS device capture is still required to verify app-level changes.
var IOS = profiles.Variant{
	HelloSpec:    &HelloChrome_158_IOS,
	HelloID:      ios.HelloID,
	Boundary:     Boundary,
	ConfigureH2:  ios.ConfigureH2,
	ConfigureH3:  ios.ConfigureH3,
	BuildHeaders: ios.BuildHeaders,
	Headers:      IOSApplier,
}
