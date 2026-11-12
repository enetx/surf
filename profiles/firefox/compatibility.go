package firefox

import (
	"github.com/enetx/surf/profiles/firefox/android"
	"github.com/enetx/surf/profiles/firefox/common"
	"github.com/enetx/surf/profiles/firefox/desktop"
	"github.com/enetx/surf/profiles/firefox/ios"
)

// DesktopApplier applies the desktop request preset to an ordered map.
var DesktopApplier = desktop.Headers

// MobileApplier applies the Android placeholder request preset to an ordered map.
var MobileApplier = android.Headers

// IOSApplier applies the iOS placeholder request preset to an ordered map.
var IOSApplier = ios.Headers

// UserAgent contains the current User-Agent values for each operating system.
var UserAgent = common.UserAgent
