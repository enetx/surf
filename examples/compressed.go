package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	URL := "https://httpbin.org/gzip"
	r := surf.NewClient().Get(URL).Do().Unwrap()
	fmt.Println(r.Body.String())

	URL = "https://httpbin.org/deflate"
	r = surf.NewClient().Get(URL).Do().Unwrap()
	fmt.Println(r.Body.String())

	URL = "https://httpbin.org/brotli"
	r = surf.NewClient().Get(URL).Do().Unwrap()
	fmt.Println(r.Body.String())
}
