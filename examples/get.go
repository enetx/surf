package main

import (
	"fmt"
	"log"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	type headers struct {
		UserAgent g.Slice[g.String] `json:"User-Agent"`
	}

	type Get struct {
		headers `json:"headers"`
	}

	r := surf.NewClient().Get("http://httpbingo.org/get").Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	var get Get

	r.Ok().Body.JSON(&get)

	fmt.Println(get.headers.UserAgent.Get(0))
	fmt.Println(r.Ok().UserAgent)
}
