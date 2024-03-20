package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	URL := "https://httpbin.org/gzip"
	r, _ := surf.NewClient().Get(URL).Do()
	fmt.Println(r.Body.String())

	URL = "https://httpbin.org/deflate"
	r, _ = surf.NewClient().Get(URL).Do()
	fmt.Println(r.Body.String())

	URL = "https://httpbin.org/brotli"
	r, _ = surf.NewClient().Get(URL).Do()
	fmt.Println(r.Body.String())
}
