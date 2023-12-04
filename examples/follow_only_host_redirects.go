package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
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
