package main

import (
	"fmt"
	"log"

	"github.com/enetx/g"
	"github.com/enetx/g/pool"
	"github.com/enetx/surf"
)

func main() {
	var urls []g.String

	urls = append(urls, "https://tls.peet.ws/api/all")
	urls = append(urls, "https://www.google.com")
	urls = append(urls, "https://dzen.ru")

	cli := surf.NewClient().
		Builder().
		Singleton(). // for reuse client
		Impersonate().
		// Chrome().
		FireFox().
		Build()

	defer cli.CloseIdleConnections()

	p := pool.New[*surf.Response]()

	for _, url := range urls {
		p.Go(cli.Get(url).Do)
	}

	for r := range p.Wait() {
		if r.IsErr() {
			log.Fatal(r.Err())
		}

		r.Ok().Debug().Response().Print()
		fmt.Println()
	}

	fmt.Println("FINISH")
}
