package main

import (
	"fmt"
	"log"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
)

func main() {
	type Headers struct {
		Headers struct {
			Referer   []string `json:"Referer"`
			UserAgent []string `json:"User-Agent"`
		} `json:"headers"`
	}

	const url = "https://httpbingo.org/headers"

	h1 := g.Map[string, string]{"Referer": "Hell"}
	// h2 := map[string]string{"Referer": "Paradise"}

	req := surf.NewClient().
		Builder().
		SetHeaders(h1).
		AddHeaders(header.REFERER, "Paradise").
		Build().
		Unwrap().
		Get(url)

	r := req.Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	resp := r.Ok()

	var headers Headers

	resp.Body.JSON(&headers)

	fmt.Println(resp.Headers)            // response headers
	fmt.Println(req.GetRequest().Header) // request headers

	fmt.Println(resp.Referer())                              // return first only
	fmt.Println(req.GetRequest().Header.Get(header.REFERER)) // return first only

	fmt.Println(headers.Headers.Referer)
}
