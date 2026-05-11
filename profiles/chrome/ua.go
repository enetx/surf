package chrome

import (
	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
)

// SecCHUA is the static value of the sec-ch-ua header for Chrome 145 (Chromium brand list).
// If the mobile sec-ch-ua diverges from desktop, introduce SecCHUAMobile here and wire it into
// chrome.Mobile in variant.go.
const SecCHUA = `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`

// UserAgent maps every supported impersonated OS to its Chrome 145 User-Agent string.
// It is shared between Desktop and Mobile variants — UA strings are an OS property, not a
// form-factor property (Chrome on Android always identifies as mobile, Chrome on Windows
// always as desktop, regardless of which fingerprint variant is dispatched).
var UserAgent = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
	profiles.MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
	profiles.Linux:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
	profiles.Android: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.7632.26 Mobile Safari/537.36",
	profiles.IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 26_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/145.0.7632.55 Mobile/15E148 Safari/604.1",
}

// Platform maps every supported impersonated OS to its sec-ch-ua-platform header value.
var Platform = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: `"Windows"`,
	profiles.MacOS:   `"macOS"`,
	profiles.Linux:   `"Linux"`,
	profiles.Android: `"Android"`,
	profiles.IOS:     `"iOS"`,
}
