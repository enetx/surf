package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
)

func main() {
	r, _ := surf.NewClient().Get("https://httpbingo.org/encoding/utf8").Do()
	fmt.Println(r.Body.String())

	r, _ = surf.NewClient().Get("http://vk.com").Do()
	fmt.Println(r.Body.UTF8())
}
