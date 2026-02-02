package main

import (
	"github.com/enetx/g"
	"github.com/enetx/g/pool"
	"github.com/enetx/surf"
)

func main() {
	p := pool.New[*surf.Response]().Limit(5)

	urls := g.SliceOf[g.String]("https://httpbingo.org/get").
		Iter().
		Cycle().
		Chan(p.GetContext())

	cli := surf.NewClient()

	var i int

	for URL := range urls {
		p.Go(func() g.Result[*surf.Response] {
			r := cli.Get(URL).Do()
			if r.IsOk() && r.Ok().StatusCode == 200 {
				p.Cancel()
			}
			return r
		})

		i++
		println(i)
	}

	for r := range p.Wait() {
		if r.IsOk() {
			r.Ok().Body.Limit(10).String().Unwrap().Print()
		}
	}
}
