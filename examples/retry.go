package main

import (
	"fmt"
	"log"
	"time"

	"github.com/enetx/surf"
)

func main() {
	cli := surf.NewClient().Builder().
		// Retry(2, time.Millisecond*50).
		// Retry(2, time.Millisecond*50, 500).
		Retry(2, time.Millisecond*50, 500, 503).
		Build().
		Unwrap()

	for i := 0; i < 3; i++ {
		r := cli.Get("http://httpbingo.org/unstable").Do()
		if r.IsErr() {
			log.Fatal(r.Err())
		}

		fmt.Println("StatusCode:", r.Ok().StatusCode, "Attempts:", r.Ok().Attempts)
		r.Ok().Debug().Request().Print()
	}
}
