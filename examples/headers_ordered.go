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
	oh.Insert(":method", "")
	oh.Insert(":authority", "")
	oh.Insert(":scheme", "")
	oh.Insert(":path", "")
	oh.Insert("1", "1")
	oh.Insert("User-Agent", "")
	oh.Insert("Accept-Encoding", "gzip")
	oh.Insert("2", "2")
	oh.Insert("Content-Type", "")
	oh.Insert("Content-Length", "")
	oh.Insert("3", "3")
	oh.Insert("4", "4")

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
