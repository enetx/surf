package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	cli := surf.NewClient().
		Builder().JA().Firefox().
		ForceHTTP2().
		Build().
		Unwrap()

	r := cli.
		Get("https://tls.peet.ws/api/all").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Proto)

	r.Ok().Debug().Request().Response(true).Print()
}
