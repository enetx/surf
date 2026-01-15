package main

import (
	"fmt"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	type Get struct {
		Headers struct {
			UserAgent []string `json:"User-Agent"`
		} `json:"headers"`
	}

	url := g.String("https://httpbingo.org/get")

	cli := surf.NewClient()

	r := cli.Get(url).Do().Unwrap()

	get := new(Get)
	r.Body.JSON(&get)

	fmt.Printf("default user agent: %s\n", get.Headers.UserAgent[0])

	// change user-agent header
	r = cli.Builder().UserAgent("From root with love!!!").Build().Unwrap().Get(url).Do().Unwrap()

	get = new(Get)
	r.Body.JSON(&get)

	fmt.Printf("changed user agent: %s\n", get.Headers.UserAgent[0])
	fmt.Println(r.UserAgent)
}
