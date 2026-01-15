package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		CacheBody().
		Build().
		Unwrap().
		Get("http://httpbingo.org/get").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Body.Limit(10).String())
	fmt.Println(r.Ok().Body.String()) // print cached body
}
