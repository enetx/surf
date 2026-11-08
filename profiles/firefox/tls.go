package firefox

import (
	"github.com/enetx/surf/profiles/firefox/android"
	"github.com/enetx/surf/profiles/firefox/desktop"
)

// HelloFirefox_159 is the current desktop TLS template.
var HelloFirefox_159 = desktop.NewClientHelloSpec()

// HelloFirefox_148_Mobile is the current Android placeholder TLS profile.
var HelloFirefox_148_Mobile = android.HelloID
