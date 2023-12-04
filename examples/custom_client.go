package main

import (
	"log"
	"time"

	"gitlab.com/x0xO/surf"
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
