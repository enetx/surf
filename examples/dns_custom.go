package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		DNS("127.0.0.1:53"). // local dns
		// DNS("1.1.1.1:53"). // cloudflare dns
		// DNS("127.0.0.1:9053"). // tor dns
		// DNS("8.8.8.8:53").     // google dns
		// DNS("9.9.9.9:53").     // quad9 dns
		Build().
		Unwrap().
		Get("http://httpbingo.org/get").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Body.String())
}
