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

	err := cli.Get("https://google.com").Do().Err()
	if err != nil {
		log.Fatal(err)
	}
}
