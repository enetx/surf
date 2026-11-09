package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		Impersonate().Chrome().
		NotFollowRedirects().
		Build().
		Unwrap().
		Get("http://google.com").
		Do().
		Unwrap()

	for r.StatusCode.IsRedirection() {
		fmt.Println(r.StatusCode, "->", r.Location())
		r = r.Get(r.Location()).Do().Unwrap()
	}

	fmt.Println(r.StatusCode, r.StatusCode.Text())

	// 301 -> http://www.google.com/
	// 302 -> https://www.google.com/?gws_rd=ssl
	// 200 OK
}
