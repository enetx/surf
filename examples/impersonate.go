package main

import (
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	// http2.VerboseLogs = true // http2 logs

	url := "https://tls.peet.ws/api/all"

	opt := surf.NewOptions()

	// opt.Impersonate().Chrome120()
	opt.Impersonate().FireFox120()

	r, err := surf.NewClient().SetOptions(opt).Get(url).Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Body.String().Print()
}
