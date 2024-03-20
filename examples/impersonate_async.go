package main

import (
	"fmt"
	"sync"

	"github.com/enetx/surf"
)

func main() {
	opt := surf.NewOptions()
	opt.Singleton() // for reuse client

	opt.Impersonate().Chrome()

	var urls []string

	urls = append(urls, "https://tls.peet.ws/api/all")
	urls = append(urls, "https://www.google.com")
	urls = append(urls, "https://dzen.ru")

	cli := surf.NewClient().SetOptions(opt)
	defer cli.CloseIdleConnections()

	var wg sync.WaitGroup

	for _, url := range urls {
		wg.Add(1)

		go func(url string) {
			defer wg.Done()

			r, err := cli.Get(url).Do()
			if err != nil {
				fmt.Println(err)
				return
			}

			r.Debug().Response().Print()
			fmt.Println()
		}(url)
	}

	wg.Wait()

	fmt.Println("FINISH")
}
