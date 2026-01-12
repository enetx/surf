package main

import (
	"fmt"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	start := time.Now()

	cli := surf.NewClient().
		Builder().
		Singleton().
		Session().
		Impersonate().
		Firefox().
		Build()

	g.SliceOf(g.String("httpbingo.org/get")).
		Iter().
		Map(func(s g.String) g.String { return "http://" + s }).
		Cycle().
		Take(100).
		Parallel(10).
		ForEach(func(s g.String) {
			if r := cli.Get(s).Do(); r.IsOk() {
				r.Ok().Body.Limit(10).String().Println()
			}
		})

	cli.CloseIdleConnections()

	elapsed := time.Since(start)
	fmt.Printf("elapsed: %v\n", elapsed)

	// urls := g.SliceOf[g.String]("https://httpbingo.org/get").
	// 	Iter().
	// 	Cycle().
	// 	Take(100).
	// 	Collect()
	//
	// pool := pool.New[*surf.Response]().Limit(10)
	// cli := surf.NewClient().
	// 	Builder().
	// 	Impersonate().
	// 	Firefox().
	// 	Build()
	//
	// for _, URL := range urls {
	// 	pool.Go(cli.Get(URL).Do)
	// }
	//
	// for r := range pool.Wait() {
	// 	if r.IsOk() {
	// 		r.Ok().Body.Limit(10).String().Print()
	// 	}
	// }
	//
	// elesped := time.Since(start)
	// fmt.Printf("elesped: %v\n", elesped)
}
