package main

import (
	"fmt"
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
	url = "https://tls.peet.ws/api/all"
	// url = "https://cloudflare.manfredi.io/test/"
	// url = "https://chat.openai.com/api/auth/csrf"
	// url = "https://www.facebook.com"

	cli := surf.NewClient().
		Builder().
		// Proxy("http://127.0.0.1:8080").
		// Proxy("socks5://127.0.0.1:9050").
		Impersonate().
		// IOS().
		// Android().
		// FireFox().
		Chrome().
		Build()

	r := cli.
		Get(url).
		// Post(url, g.String("test").Encode().JSON().Ok()).
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Time)

	r.Ok().Debug().Request().Response(true).Print()
}
