package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	opt := surf.NewOptions().NotFollowRedirects()

	r, _ := surf.NewClient().SetOptions(opt).Get("http://google.com").Do()

	for r.StatusCode.IsRedirection() {
		fmt.Println(r.StatusCode, "->", r.Location())
		r, _ = r.Get(r.Location()).Do()
	}

	fmt.Println(r.StatusCode, r.StatusCode.Text())
}
