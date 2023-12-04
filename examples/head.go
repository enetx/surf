package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	r, err := surf.NewClient().Head("http://httpbingo.org/get").Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Status)
}
