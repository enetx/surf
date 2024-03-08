package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	type Headers struct {
		Headers struct {
			Referer   []string `json:"Referer"`
			UserAgent []string `json:"User-Agent"`
		} `json:"headers"`
	}

	URL := "https://httpbingo.org/headers"

	h1 := map[string]string{"Referer": "Hell"}
	// h2 := map[string]string{"Referer": "Paradise"}

	req := surf.NewClient().Get(URL).SetHeaders(h1) //.AddHeaders(h2)
	req.GetRequest().Header.Add("Referer", "Paradise")

	r, err := req.Do()
	if err != nil {
		log.Fatal(err)
	}

	var headers Headers

	r.Body.JSON(&headers)

	fmt.Println(headers.Headers.Referer)
	fmt.Println(r.Referer()) // return first only

	fmt.Println(r.Headers)
	fmt.Println(r.Headers.Values("date"))
}
