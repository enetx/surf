package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
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
