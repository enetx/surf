package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
)

func main() {
	// use only for debugging, not in async mode, no concurrency safe

	r, _ := surf.NewClient().
		SetOptions(surf.NewOptions().History()).
		Get("https://httpbingo.org/redirect/6").
		Do()

	fmt.Println(r.History.Referrers())
	fmt.Println(r.History.StatusCodes())
	fmt.Println(r.History.Cookies())
	fmt.Println(r.History.URLS())
}
