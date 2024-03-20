package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r, err := surf.NewClient().Head("http://httpbingo.org/head").Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Debug().Request().Response().Print()

	fmt.Println()
	fmt.Println(r.Time)
}
