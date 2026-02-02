package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	type ContentType struct {
		Headers struct {
			ContentType []string `json:"Content-Type"`
		} `json:"headers"`
	}

	r := surf.NewClient().
		Builder().
		ContentType("secret/content-type").
		Build().
		Unwrap().
		Get("https://httpbingo.org/get").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	var contentType ContentType

	r.Ok().Body.JSON(&contentType)

	fmt.Println(contentType.Headers.ContentType)
}
