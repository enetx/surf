package main

import (
	"fmt"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	start := time.Now()

	g.SliceOf(g.String("https://httpbingo.org/get")).
		Iter().
		Cycle().
		Take(100).
		Parallel(100).
		ForEach(func(s g.String) {
			if r := surf.NewClient().Get(s).Do(); r.IsOk() {
				r.Ok().Body.Limit(10).String().Println()
			}
		})

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
	// 	FireFox().
	// 	Build()
	//
	// for _, URL := range urls {
	// 	pool.Go(cli.Get(URL).Do)
	// }
	//
	// for r := range pool.Wait().Iter() {
	// 	if r.IsOk() {
	// 		r.Ok().Body.Limit(10).String().Print()
	// 	}
	// }
	//
	// elesped := time.Since(start)
	// fmt.Printf("elesped: %v\n", elesped)
}
