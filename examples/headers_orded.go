package main

import (
	"log"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/surf"
)

func main() {
	url := "https://tls.peet.ws/api/all"

	orderedHeaders := g.NewMapOrd[string, string]().
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

	opt := surf.NewOptions().UserAgent("root")

	r, err := surf.NewClient().SetOptions(opt).Get(url).SetHeaders(orderedHeaders).Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Debug().Request(true).Response(true).Print()
}
