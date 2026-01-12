package main

import (
	"github.com/enetx/surf"
)

func main() {
	cli := surf.NewClient()

	cli.Get("https://httpbin.org/gzip").Do().Ok().Body.String().Print()
	cli.Get("https://httpbin.org/deflate").Do().Ok().Body.String().Print()
	cli.Get("https://httpbin.org/brotli").Do().Ok().Body.String().Print()
}
