package main

import (
	"fmt"

	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
)

func main() {
	opt := surf.NewOptions().NotFollowRedirects()

	r, _ := surf.NewClient().SetOptions(opt).Get("http://google.com").Do()

	for r.StatusCode != 200 {
		fmt.Println(r.StatusCode, "->", r.Headers.Get(header.LOCATION))
		r, _ = r.Get(r.Headers.Get(header.LOCATION)).Do()
	}
}
