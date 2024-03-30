package main

import (
	"log"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	url := "https://tls.peet.ws/api/all"

	orderedHeaders := g.NewMapOrd[string, string]()
	orderedHeaders.
		Set(":method", "").
		Set(":authority", "").
		Set(":scheme", "").
		Set(":path", "").
		Set("1", "1").
		Set("Accept-Encoding", "gzip").
		Set("2", "2").
		Set("User-Agent", "").
		Set("3", "3").
		Set("4", "4")

	r := surf.NewClient().
		Builder().
		UserAgent("root").
		Build().
		Get(url).
		SetHeaders(orderedHeaders).
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Request(true).Response(true).Print()
}
