package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	type basicAuth struct {
		Authorized bool   `json:"authorized"`
		User       string `json:"user"`
	}

	URL := "https://httpbingo.org/basic-auth/root/passwd"

	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().BasicAuth("root:passwd")).
		Get(URL).
		Do()
		// r, err := surf.NewClient().
		// 	SetOptions(surf.NewOptions().BasicAuth([]string{"root", "passwd"})).
		// 	Get(URL).
		// 	Do()
		// r, err := surf.NewClient().
		// 	SetOptions(surf.NewOptions().BasicAuth(map[string]string{"root": "passwd"})).
		// 	Get(URL).
		// 	Do()
	if err != nil {
		log.Fatal(err)
	}

	var ba basicAuth

	r.Body.JSON(&ba)

	fmt.Printf("authorized: %v, user: %s", ba.Authorized, ba.User)
}
