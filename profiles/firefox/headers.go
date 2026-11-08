package firefox

import (
	"github.com/enetx/surf/profiles/firefox/android"
	"github.com/enetx/surf/profiles/firefox/desktop"
	"github.com/enetx/surf/profiles/firefox/ios"
)

// DesktopApplier applies the desktop request-header pipeline.
var DesktopApplier = desktop.Headers

// MobileApplier applies the Android request-header pipeline.
var MobileApplier = android.Headers

// IOSApplier applies the iOS request-header pipeline.
var IOSApplier = ios.Headers
