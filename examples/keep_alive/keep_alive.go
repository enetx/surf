package main

import (
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		DisableKeepAlive().
		Build().
		Unwrap().
		Get("http://www.keycdn.com").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Response().Print() // Connection: close
}
