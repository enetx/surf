package main

import (
	"fmt"
	"sync"

	"github.com/enetx/surf"
)

func main() {
	urls := make([]string, 100)

	for i := 0; i < 100; i++ {
		urls[i] = "https://httpbingo.org/get"
	}

	urlsChan := make(chan string)

	go func() {
		defer close(urlsChan)

		for _, URL := range urls {
			urlsChan <- URL
		}
	}()

	cli := surf.NewClient()

	var wg sync.WaitGroup

	for range 10 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for URL := range urlsChan {
				r := cli.Get(URL).Do()
				if r.IsErr() {
					fmt.Println(r.Err())
					return
				}

				resp := r.Ok()

				resp.Body.Limit(10).String().Print()
				resp.Release() // sync pool
			}
		}()
	}

	wg.Wait()
}
