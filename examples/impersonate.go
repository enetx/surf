package main

import (
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	// http2.VerboseLogs = true // http2 logs

	// url := "https://tls.peet.ws/api/all"
	url := "https://chat.openai.com/"

	opt := surf.NewOptions().
		// Proxy("http://127.0.0.1:18080")
		// Proxy("http://127.0.0.1:2080")
		Proxy("socks5://127.0.0.1:2080")

	// opt.Impersonate().Chrome120()
	opt.Impersonate().FireFox120()

	r, err := surf.NewClient().SetOptions(opt).Get(url).Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Debug().Request().Response(true).Print()
}
