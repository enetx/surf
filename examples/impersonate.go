package main

import (
	"log"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	// https://browserleaks.com/tls

	// http2.VerboseLogs = true // http2 logs
	var url g.String

	// url = "https://localhost"

	// url = "https://nowsecure.nl"
	// url = "https://www.moscowbooks.ru"
	// url = "https://tls.peet.ws/api/clean"
	url = "https://tls.peet.ws/api/all"
	// url = "https://tls.browserleaks.com/json"
	// url = "https://cloudflare.manfredi.io/test/"
	// url = "https://chat.openai.com/api/auth/csrf"
	// url = "https://www.facebook.com"

	cli := surf.NewClient().
		Builder().
		// DNS("1.1.1.1:53").
		// DNSOverTLS().Google().
		// Proxy("http://127.0.0.1:2080").
		// Proxy("socks4://127.0.0.1:2080").
		// Proxy("socks5://127.0.0.1:2080").
		Impersonate().
		// MacOS().
		// IOS().
		// Android().
		Firefox().
		// FirefoxPrivate().
		// Chrome().
		// SetHeaders(map[string]string{
		// 	"Accept-Encoding": "gzip, deflate",
		// }).
		Build().
		Unwrap()

	r := cli.
		Get(url).
		// Post(url, g.String("test").Encode().JSON().Ok()).
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Body.String().Unwrap().Println()

	// fmt.Println(r.Ok().Time)

	// r.Ok().Debug().Request().Response(true).Print()
}
