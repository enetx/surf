package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
)

func main() {
	type Get struct {
		Headers struct {
			UserAgent []string `json:"User-Agent"`
		} `json:"headers"`
	}

	URL := "https://httpbingo.org/get"

	cli := surf.NewClient()

	r, _ := cli.Get(URL).Do()

	get := new(Get)
	r.Body.JSON(&get)

	fmt.Printf("default user agent: %s\n", get.Headers.UserAgent[0])

	// change user-agent header
	opt := surf.NewOptions().UserAgent("From root with love!!!")

	r, _ = cli.SetOptions(opt).Get(URL).Do()

	get = new(Get)
	r.Body.JSON(&get)

	fmt.Printf("changed user agent: %s\n", get.Headers.UserAgent[0])
	fmt.Println(r.UserAgent)
}
