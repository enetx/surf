package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().Head("http://httpbingo.org/head").Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Request().Response().Print()

	fmt.Println()
	fmt.Println(r.Ok().Time)
}
