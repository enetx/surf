package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	type ContentType struct {
		Headers struct {
			ContentType []string `json:"Content-Type"`
		} `json:"headers"`
	}

	opt := surf.NewOptions().ContentType("secret/content-type")

	r, err := surf.NewClient().SetOptions(opt).Get("https://httpbingo.org/get").Do()
	if err != nil {
		log.Fatal(err)
	}

	var contentType ContentType

	r.Body.JSON(&contentType)

	fmt.Println(contentType.Headers.ContentType)
}
