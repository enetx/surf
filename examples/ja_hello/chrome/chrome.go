package main

import (
	"log"

	"github.com/enetx/surf"
)

func main() {

	const url = "https://tls.peet.ws/api/all"

	cli := surf.NewClient().
		Builder().
		JA().Chrome157().
		Build().
		Unwrap()

	r := cli.Get(url).Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Request(true).Response(true).Print()
}
