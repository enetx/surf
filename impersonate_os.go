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

const chromeSecCHUA = `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`

var chromePlatform = map[ImpersonateOS]g.String{
	windows: `"Windows"`,
	macos:   `"macOS"`,
	linux:   `"Linux"`,
	android: `"Android"`,
	ios:     `"iOS"`,
}

var chromeUserAgent = map[ImpersonateOS]g.String{
	windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	macos:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	linux:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	android: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	ios:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.154 Mobile/15E148 Safari/604.1",
}

var firefoxUserAgent = map[ImpersonateOS]g.String{
	windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
	macos:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0",
	linux:   "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
	android: "Mozilla/5.0 (Android 16; Mobile; rv:144.0) Gecko/144.0 Firefox/144.0",
	ios:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/144.0 Mobile/15E148 Safari/605.1.15",
}

var torUserAgent = map[ImpersonateOS]g.String{
	windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
	macos:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
	linux:   "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	android: "Mozilla/5.0 (Android 10; Mobile; rv:128.0) Gecko/134.0 Firefox/128.0",
	ios:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/128.3 Mobile/15E148 Safari/605.1.15",
}

func (imo ImpersonateOS) mobile() g.String {
	if imo == android || imo == ios {
		return "?1"
	}

	return "?0"
}
