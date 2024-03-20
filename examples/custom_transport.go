package main

import (
	"log"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/surf"
)

func main() {
	cli := surf.NewClient()

	// transport custom settings
	cli.GetTransport().(*http.Transport).TLSHandshakeTimeout = time.Nanosecond

	_, err := cli.Get("https://google.com").Do()
	if err != nil {
		log.Fatal(err)
	}
}
