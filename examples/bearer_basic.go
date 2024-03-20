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

	URL := "https://httpbingo.org/headers"

	opt := surf.NewOptions().BasicAuth("root:toor").BearerAuth("bearer").CacheBody()

	r, err := surf.NewClient().SetOptions(opt).Get(URL).Do()
	if err != nil {
		log.Fatal(err)
	}

	var headers Headers

	r.Body.JSON(&headers)

	fmt.Println(headers.Headers.Authorization)
}
