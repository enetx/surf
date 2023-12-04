package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
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
