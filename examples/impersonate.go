package main

import (
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	// http2.VerboseLogs = true // http2 logs

	// url := "https://www.moscowbooks.ru"
	// url := "https://tls.peet.ws/api/all"
	url := "https://chat.openai.com/api/auth/csrf"
	// url := "https://chat.openai.com/auth/login"

	opt := surf.NewOptions()

	opt.
		// Proxy("http://127.0.0.1:18080")
		Proxy("socks5://127.0.0.1:2080")

	opt.Impersonate().
		// Chrome()
		FireFox()

	r, err := surf.NewClient().SetOptions(opt).Get(url).Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Debug().Request().Response(true).Print()
}
