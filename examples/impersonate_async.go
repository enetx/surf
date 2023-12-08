package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gitlab.com/x0xO/surf"
)

func main() {
	url := "https://tls.peet.ws/api/all"
	// url := "https://www.google.com"

	opt := surf.NewOptions()
	opt.Impersonate().Chrome()

	// opt.Proxy("socks5://localhost:9050")

	var urls []string

	urls = append(urls, url)
	urls = append(urls, url)
	urls = append(urls, url)
	urls = append(urls, url)
	urls = append(urls, url)
	urls = append(urls, url)

	// for _, url := range urls {
	// 	ctx, _ := context.WithTimeout(context.Background(), time.Second*30)

	// 	r, err := surf.NewClient().SetOptions(opt).Get(url).WithContext(ctx).Do()
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}

	// 	r.Debug().Response().Print()
	// }

	var wg sync.WaitGroup

	for _, url := range urls {
		wg.Add(1)

		go func(url string) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			defer cancel()

			r, err := surf.NewClient().SetOptions(opt).Get(url).WithContext(ctx).Do()
			if err != nil {
				fmt.Println(err)
				return
			}

			r.Debug().Response().Print()
		}(url)
	}

	wg.Wait()

	fmt.Println("FINISH")
}
