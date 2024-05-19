package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/enetx/surf"
)

func main() {
	var urls []string

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

	var wg sync.WaitGroup

	for _, url := range urls {
		wg.Add(1)

		go func(url string) {
			defer wg.Done()

			r := cli.Get(url).Do()
			if r.IsErr() {
				log.Fatal(r.Err())
			}

			defer r.Ok().Release()

			r.Ok().Debug().Response().Print()
			fmt.Println()
		}(url)
	}

	wg.Wait()

	fmt.Println("FINISH")
}
