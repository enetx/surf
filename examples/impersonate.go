package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	// http2.VerboseLogs = true // http2 logs

	// url := "https://www.moscowbooks.ru"
	url := "https://tls.peet.ws/api/all"
	// url := "https://chat.openai.com/api/auth/csrf"
	// url := "https://chat.openai.com/auth/login"
	// url := "https://www.facebook.com"

	r := surf.NewClient().
		Builder().
		// Proxy("http://127.0.0.1:2080").
		// Proxy("socks5://127.0.0.1:2080").
		Impersonate().
		// FireFox().
		Chrome().
		Build().
		Get(url).
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Time)

	r.Ok().Debug().Request().Response(true).Print()
}
