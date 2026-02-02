package main

import (
	"log"

	"github.com/enetx/surf"
)

func main() {
	// https://github.com/lwthiker/curl-impersonate/tree/main/chrome

	// const url = "https://localhost:8443"
	const url = "https://tls.peet.ws/api/all"
	// const url = "http://tools.scrapfly.io/api/fp/anything"

	cli := surf.NewClient().
		Builder().
		JA().Chrome87().
		Build().
		Unwrap()

	r := cli.Get(url).Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Request(true).Response(true).Print()
}
