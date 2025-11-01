package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().JA().Firefox().
		ForceHTTP1().
		Build().
		Get("https://tls.peet.ws/api/all").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Proto)

	r.Ok().Debug().Request().Response(true).Print()
}
