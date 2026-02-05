package main

import (
	"github.com/enetx/g"
	"github.com/enetx/g/pool"
	"github.com/enetx/surf"
)

func main() {
	ps := g.Slice[g.String]{
		"http://127.0.0.1:2080",
		"socks4://127.0.0.1:2080",
		"socks5://127.0.0.1:2080",
	}

	urls := g.SliceOf[g.String]("https://httpbingo.org/get").
		Iter().
		Cycle().
		Take(100)

	p := pool.New[*surf.Response]().Limit(10)

	for url := range urls {
		p.Go(
			surf.NewClient().
				Builder().
				Proxy(ps.Random()).
				Build().
				Unwrap().
				Get(url).Do,
		)
	}

	for r := range p.Wait() {
		if r.IsOk() {
			r.Ok().Body.Limit(10).String().Unwrap().Print()
		}
	}
}
