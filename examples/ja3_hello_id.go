package main

import (
	"log"

	"github.com/enetx/surf"
)

func main() {
	// https://github.com/lwthiker/curl-impersonate/tree/main/chrome

	url := "https://tls.peet.ws/api/all"
	// url := "http://tools.scrapfly.io/api/fp/anything"

	cli := surf.NewClient().
		Builder().
		JA3().Chrome87().
		Build()

	r := cli.Get(url).Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Request(true).Response(true).Print()
}
