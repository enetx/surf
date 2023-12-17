package main

import (
	"fmt"
	"sync"

	"gitlab.com/x0xO/surf"
)

func main() {
	opt := surf.NewOptions()
	opt.Singleton() // for reuse client

	opt.Impersonate().Chrome120()

	var urls []string

	urls = append(urls, "https://tls.peet.ws/api/all")
	urls = append(urls, "https://www.google.com")
	urls = append(urls, "https://dzen.ru")

	cli := surf.NewClient().SetOptions(opt)

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

	cli.CloseIdleConnections()

	fmt.Println("FINISH")
}
