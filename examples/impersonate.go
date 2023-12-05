package main

import (
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	url := "https://tls.peet.ws/api/all"

	opt := surf.NewOptions()

	// opt.Impersonate().Chrome()
	opt.Impersonate().FireFox()

	r, err := surf.NewClient().SetOptions(opt).Get(url).
		Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Body.String().Print()
}
