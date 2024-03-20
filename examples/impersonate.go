package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	// http2.VerboseLogs = true // http2 logs

	// url := "https://www.moscowbooks.ru"
	// url := "https://tls.peet.ws/api/all"
	url := "https://chat.openai.com/api/auth/csrf"
	// url := "https://chat.openai.com/auth/login"
	// url := "https://www.facebook.com"

	opt := surf.NewOptions()

	opt.
		// Proxy("http://127.0.0.1:2080")
		Proxy("socks5://127.0.0.1:2080")

	opt.Impersonate().
		// Chrome()
		FireFox()

	r, err := surf.NewClient().SetOptions(opt).Get(url).Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Time)

	r.Debug().Request().Response(true).Print()
}
