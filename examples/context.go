package main

import (
	"context"
	"log"
	"time"

	"github.com/enetx/surf"
)

func main() {
	URL := "https://httpbingo.org/get"

	cli := surf.NewClient()
	req := cli.Get(URL)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	resp := req.WithContext(ctx).Do()
	if resp.IsErr() {
		log.Fatal(resp.Err())
	}

	log.Println(resp.Ok().Body.String())
}
