package main

import (
	"log"
	"time"

	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/surf"
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
