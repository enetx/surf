package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/enetx/g"
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
		Firefox().
		Build()

	defer cli.CloseIdleConnections()

	var wg sync.WaitGroup

	for _, url := range urls {
		wg.Add(1)

		go func(url g.String) {
			defer wg.Done()

			r := cli.Get(url).Do()
			if r.IsErr() {
				log.Fatal(r.Err())
			}

			r.Ok().Debug().Response().Print()
			fmt.Println()
		}(url)
	}

	wg.Wait()

	fmt.Println("FINISH")
}
