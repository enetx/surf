package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r, err := surf.NewClient().Get("http://httpbingo.org/get").Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Body.Limit(10).String())
}
