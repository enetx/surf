package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().CacheBody()).
		Get("http://httpbingo.org/get").
		Do()
	if err != nil {
		log.Fatal(err)
	}

	rr(r)

	fmt.Println(r.Body.Limit(10).String())
	fmt.Println(r.Body.String()) // print cached body
}
