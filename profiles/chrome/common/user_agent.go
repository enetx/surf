package common

import (
	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
)

// SecCHUA is the native Chromium 158 Client Hints brand list used by desktop and
// Android header builders. iOS does not send Chromium Client Hints.
// https://github.com/chromium/chromium/blob/158.0.8127.18/components/embedder_support/user_agent_utils.cc
const SecCHUA = `"Not.A/Brand";v="24", "Chromium";v="158"`

// UserAgent contains Chrome 158 desktop/Android and iOS navigation identities.
// The iOS app build follows the official release; OS fields retain the verified
// device identity and its WebKit transport shape.
// All variants read the values for their operating system.
var UserAgent = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
	profiles.MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
	profiles.Linux:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
	profiles.Android: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Mobile Safari/537.36",
	profiles.IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/158.0.8127.32 Mobile/15E148 Safari/604.1",
}

// Platform maps every supported impersonated OS to its sec-ch-ua-platform header value.
var Platform = g.Map[profiles.OSKey, g.String]{
	profiles.Windows: `"Windows"`,
	profiles.MacOS:   `"macOS"`,
	profiles.Linux:   `"Linux"`,
	profiles.Android: `"Android"`,
	profiles.IOS:     `"iOS"`,
}
