package main

import (
	"log"
	"time"

	"github.com/enetx/surf"
)

func main() {
	cli := surf.NewClient()

	// client custom settings
	cli.GetClient().Timeout = time.Nanosecond

	_, err := cli.Get("https://google.com").Do()
	if err != nil {
		log.Fatal(err)
	}
}
