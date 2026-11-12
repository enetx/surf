package chrome

import (
	"github.com/enetx/surf/profiles/chrome/android"
	"github.com/enetx/surf/profiles/chrome/common"
	"github.com/enetx/surf/profiles/chrome/desktop"
	"github.com/enetx/surf/profiles/chrome/ios"
)

// DesktopApplier applies the desktop request-header pipeline.
var DesktopApplier = desktop.Headers

// MobileApplier applies the Android request-header pipeline.
var MobileApplier = android.Headers

// IOSApplier applies the iOS request-header pipeline.
var IOSApplier = ios.Headers

// SecCHUA is the current Chrome Client Hints brand list, including its branding.
const SecCHUA = common.SecCHUA

// UserAgent contains the current User-Agent values for each operating system.
var UserAgent = common.UserAgent

// Platform contains the Client Hints platform names.
var Platform = common.Platform
