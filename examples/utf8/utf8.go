package main

import "github.com/enetx/surf"

func main() {
	surf.NewClient().Get("https://httpbingo.org/encoding/utf8").Do().Ok().Body.UTF8().Unwrap().Print()
	surf.NewClient().Get("http://vk.com").Do().Ok().Body.UTF8().Unwrap().Print()
}
