package main

import (
	"log"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	// const url = "https://localhost"
	const url = "https://tls.peet.ws/api/all"

	// oh := g.NewMapOrd[string, string]()
	oh := g.NewMapOrd[g.String, g.String]()
	oh.Set(":method", "")
	oh.Set(":authority", "")
	oh.Set(":scheme", "")
	oh.Set(":path", "")
	oh.Set("1", "1")
	oh.Set("User-Agent", "")
	oh.Set("Accept-Encoding", "gzip")
	oh.Set("2", "2")
	oh.Set("Content-Type", "")
	oh.Set("Content-Length", "")
	oh.Set("3", "3")
	oh.Set("4", "4")

	r := surf.NewClient().
		Builder().
		ForceHTTP1().
		// ForceHTTP2().
		UserAgent("root").
		SetHeaders(oh).
		Build().
		Unwrap().
		// Get(url).
		Post(url, "surf").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Request(true).Response(true).Print()
}
