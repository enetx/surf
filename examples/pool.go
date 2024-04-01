package main

import (
	"log"

	"github.com/enetx/surf"
)

func main() {
	cli := surf.NewClient()

	func() {
		r := cli.Get("https://httpbingo.org/get").Do()
		if r.IsErr() {
			log.Fatal(r.Err())
		}

		defer r.Ok().Release()
	}()

	r := cli.Get("https://httpbingo.org/not_found").Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Release()

	r = cli.Get("https://httpbingo.org/not_found").Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Release()
}
