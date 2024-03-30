package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	type Headers struct {
		Headers struct {
			Referer   []string `json:"Referer"`
			UserAgent []string `json:"User-Agent"`
		} `json:"headers"`
	}

	url := "https://httpbingo.org/headers"

	h1 := map[string]string{"Referer": "Hell"}
	// h2 := map[string]string{"Referer": "Paradise"}

	req := surf.NewClient().Get(url).SetHeaders(h1) //.AddHeaders(h2)
	req.GetRequest().Header.Add("Referer", "Paradise")

	r := req.Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	var headers Headers

	r.Ok().Body.JSON(&headers)

	fmt.Println(headers.Headers.Referer)
	fmt.Println(r.Ok().Referer()) // return first only

	fmt.Println(r.Ok().Headers)
	fmt.Println(r.Ok().Headers.Values("date"))
}
