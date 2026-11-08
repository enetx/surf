package common

import (
	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
)

// SecCHUA is the Chrome 156 Client Hints brand list used by the desktop and
// Android header builders. iOS does not send Chromium Client Hints.
const SecCHUA = `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`

// UserAgent contains Chrome 156 desktop/Android and the captured Chrome 157 iOS UA.
// All variants read the values for their operating system.
var UserAgent = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
	profiles.MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
	profiles.Linux:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
	profiles.Android: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36",
	profiles.IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/157.0.8103.37 Mobile/15E148 Safari/604.1",
}

// Platform maps every supported impersonated OS to its sec-ch-ua-platform header value.
var Platform = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: `"Windows"`,
	profiles.MacOS:   `"macOS"`,
	profiles.Linux:   `"Linux"`,
	profiles.Android: `"Android"`,
	profiles.IOS:     `"iOS"`,
}
