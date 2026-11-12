package chrome

import (
	"github.com/enetx/surf/profiles/chrome/android"
	"github.com/enetx/surf/profiles/chrome/desktop"
	"github.com/enetx/surf/profiles/chrome/ios"
)

// HelloChrome_158 is the current desktop TLS template, verified against native
// Chromium 158 including server padding. The selected OS owns the User-Agent.
var HelloChrome_158 = desktop.NewClientHelloSpec()

// HelloChrome_158_Mobile is the independent current Android TLS template.
var HelloChrome_158_Mobile = android.NewClientHelloSpec()

// HelloChrome_158_IOS uses the captured WebKit TLS shape for the current iOS
// profile. Chrome's app version changes its UA; the OS owns the TLS engine.
var HelloChrome_158_IOS = ios.NewClientHelloSpec()
