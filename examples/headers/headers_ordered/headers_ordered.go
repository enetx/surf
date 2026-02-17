package main

import (
	"log"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
)

func main() {
	// const url = "https://localhost"
	const url = "https://tls.peet.ws/api/all"

	// oh := g.NewMapOrd[string, string]()
	oh := g.NewMapOrd[g.String, g.String]()

	// HTTP/2 headers
	oh.Insert(":method", "")
	oh.Insert(":authority", "")
	oh.Insert(":scheme", "")
	oh.Insert(":path", "")

	oh.Insert("1", "1")
	oh.Insert(header.USER_AGENT, "")
	oh.Insert(header.ACCEPT_ENCODING, "gzip")
	oh.Insert("2", "2")
	oh.Insert(header.CONTENT_TYPE, "")
	oh.Insert(header.CONTENT_LENGTH, "")
	oh.Insert(header.TRANSFER_ENCODING, "")
	oh.Insert("3", "3")
	oh.Insert(header.HOST, "")
	oh.Insert("4", "4")

	reader := g.NewFile("headers_ordered.go").Reader().Unwrap()

	r := surf.NewClient().
		Builder().
		ForceHTTP1().
		// ForceHTTP2().
		SetHeaders(oh).
		Build().
		Unwrap().
		// Get(url).
		// Post(url).Body("").
		// Post(url).Body("root").
		Post(url).Body(reader).
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Request(true).Response(true).Print()
}
