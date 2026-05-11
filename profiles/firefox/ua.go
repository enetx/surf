package firefox

import (
	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
)

// UserAgent maps every supported impersonated OS to its Firefox 148 User-Agent string.
// Shared between Desktop and Mobile variants — UA strings are an OS property, not a
// form-factor property. iOS Firefox uses the FxiOS variant (under the hood it is WebKit).
var UserAgent = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
	profiles.MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0",
	profiles.Linux:   "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0",
	profiles.Android: "Mozilla/5.0 (Android 16; Mobile; rv:148.0) Gecko/148.0 Firefox/148.0",
	profiles.IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/148.0 Mobile/15E148 Safari/605.1.15",
}
