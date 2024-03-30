package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().Get("https://httpbingo.org/encoding/utf8").Do().Unwrap()
	fmt.Println(r.Body.String())

	r = surf.NewClient().Get("http://vk.com").Do().Unwrap()
	fmt.Println(r.Body.UTF8())
}
