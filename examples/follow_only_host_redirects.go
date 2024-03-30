package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		FollowOnlyHostRedirects().
		Build().
		Get("google.com").
		// Get("www.google.com").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Body.String())
}
