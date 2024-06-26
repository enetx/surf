package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		ForwardHeadersOnRedirect().
		Build().
		Get("google.com").
		AddHeaders(map[string]string{"Referer": "surf.xoxo"}).
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Referer())
}
