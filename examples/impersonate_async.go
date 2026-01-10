package main

import (
	"fmt"
	"log"

	"github.com/enetx/g"
	"github.com/enetx/g/pool"
	"github.com/enetx/surf"
)

func main() {
	urls := g.NewSlice[g.String]()
	urls.Push("https://tls.peet.ws/api/all")
	urls.Push("https://www.google.com")
	urls.Push("https://dzen.ru")

	cli := surf.NewClient().
		Builder().
		Impersonate().
		// Chrome().
		Firefox().
		Build()

	p := pool.New[*surf.Response]()

	for _, url := range urls {
		p.Go(cli.Get(url).Do)
	}

	for r := range p.Wait() {
		if r.IsErr() {
			log.Println(r.Err())
			continue
		}

		r.Ok().Debug().Response().Print()
		fmt.Println()
	}

	fmt.Println("FINISH")
}
