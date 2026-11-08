package chrome

import (
	"github.com/enetx/surf/profiles/chrome/android"
	"github.com/enetx/surf/profiles/chrome/desktop"
	"github.com/enetx/surf/profiles/chrome/ios"
)

// HelloChrome_156 is the current desktop TLS template.
var HelloChrome_156 = desktop.NewClientHelloSpec()

// HelloChrome_156_Mobile is the independent current Android TLS template.
var HelloChrome_156_Mobile = android.NewClientHelloSpec()

// HelloChrome_157_IOS is the current WebKit TLS template for Chrome on iOS.
var HelloChrome_157_IOS = ios.NewClientHelloSpec()
