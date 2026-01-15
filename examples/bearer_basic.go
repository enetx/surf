package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	type Headers struct {
		Headers struct {
			Authorization []string `json:"Authorization"`
		} `json:"headers"`
	}

	cli := surf.NewClient().
		Builder().
		BasicAuth("root:toor").
		BearerAuth("bearer").
		CacheBody().
		Build().
		Unwrap()

	r := cli.Get("https://httpbingo.org/headers").Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	var headers Headers

	r.Ok().Body.JSON(&headers)

	fmt.Println(headers.Headers.Authorization)
}
