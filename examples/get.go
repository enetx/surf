package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/surf"
)

func main() {
	type headers struct {
		UserAgent g.Slice[g.String] `json:"User-Agent"`
	}

	type Get struct {
		headers `json:"headers"`
	}

	r, err := surf.NewClient().Get("http://httpbingo.org/get").Do()
	if err != nil {
		log.Fatal(err)
	}

	var get Get

	r.Body.JSON(&get)

	fmt.Println(get.headers.UserAgent.Get(0))
	fmt.Println(r.UserAgent)
}
