package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().CacheBody()).
		Get("http://httpbingo.org/get").
		Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Body.Limit(10).String())
	fmt.Println(r.Body.String()) // print cached body
}
