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
		AddHeaders(map[string]string{"Referer": "surf.xoxo"}).
		Build().
		Get("http://google.com").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Referer())
}
