package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	type basicAuth struct {
		Authorized bool   `json:"authorized"`
		User       string `json:"user"`
	}

	r := surf.NewClient().
		Builder().
		BasicAuth("root:passwd").
		Build().
		Unwrap().
		Get("https://httpbingo.org/basic-auth/root/passwd").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	var ba basicAuth

	r.Ok().Body.JSON(&ba)

	fmt.Printf("authorized: %v, user: %s", ba.Authorized, ba.User)
}
