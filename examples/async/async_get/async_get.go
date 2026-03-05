package main

import (
	"fmt"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/g/pool"
	"github.com/enetx/surf"
)

func main() {
	start := time.Now()

	urls := g.SliceOf[g.String]("https://httpbingo.org/get").
		Iter().
		Cycle().
		Take(100).
		Collect()

	pool := pool.New[*surf.Response]().Limit(10)

	cli := surf.NewClient().
		Builder().
		Impersonate().
		Firefox().
		Build().
		Unwrap()

	for _, URL := range urls {
		pool.Go(cli.Get(URL).Do)
	}

	for r := range pool.Wait() {
		if r.IsOk() {
			r.Ok().Body.Limit(10).String().Unwrap().Print()
		}
	}

	elesped := time.Since(start)
	fmt.Printf("elesped: %v\n", elesped)
}
