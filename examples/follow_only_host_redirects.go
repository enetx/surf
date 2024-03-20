package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	opt := surf.NewOptions().FollowOnlyHostRedirects()

	r, err := surf.NewClient().SetOptions(opt).
		Get("google.com").
		// Get("www.google.com").
		Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Body.String())
}
