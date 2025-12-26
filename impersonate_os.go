package surf

import "github.com/enetx/g"

// ImpersonateOS defines the operating system to impersonate in User-Agent strings.
type ImpersonateOS int

const (
	windows ImpersonateOS = iota // Default, Microsoft Windows.
	macos                        // macOS by Apple.
	linux                        // Generic Linux.
	android                      // Android by Google.
	ios                          // iOS by Apple.
)

const chromeSecCHUA = `"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"`

var chromePlatform = map[ImpersonateOS]g.String{
	windows: `"Windows"`,
	macos:   `"macOS"`,
	linux:   `"Linux"`,
	android: `"Android"`,
	ios:     `"iOS"`,
}

var chromeUserAgent = map[ImpersonateOS]g.String{
	windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
	macos:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
	linux:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
	android: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
	ios:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/142.0.7444.77 Mobile/15E148 Safari/604.1",
}

var firefoxUserAgent = map[ImpersonateOS]g.String{
	windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0",
	macos:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0",
	linux:   "Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0",
	android: "Mozilla/5.0 (Android 16; Mobile; rv:146.0) Gecko/146.0 Firefox/146.0",
	ios:     "Mozilla/5.0 (iPhone; CPU iPhone OS 26_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/146.0 Mobile/15E148 Safari/605.1.15",
}

func (imo ImpersonateOS) mobile() g.String {
	if imo == android || imo == ios {
		return "?1"
	}

	return "?0"
}
