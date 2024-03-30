package main

import (
	"fmt"
	"log"
	"time"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().Timeout(time.Second).Build().
		Get("httpbingo.org/delay/2").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().StatusCode)
}
