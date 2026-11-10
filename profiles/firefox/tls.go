package firefox

import (
	"github.com/enetx/surf/profiles/firefox/android"
	"github.com/enetx/surf/profiles/firefox/desktop"
)

// HelloFirefox_160 is the current desktop TLS template, verified against
// independent Firefox 160 captures.
var HelloFirefox_160 = desktop.NewClientHelloSpec()

// HelloFirefox_148_Mobile is the current Android placeholder TLS profile.
var HelloFirefox_148_Mobile = android.HelloID
