package main

import (
	"fmt"
	"sync"

	"gitlab.com/x0xO/surf"
)

func main() {
	var urls []*surf.AsyncURL
	for i := 0; i < 10; i++ {
		urls = append(urls, surf.NewAsyncURL("https://tls.peet.ws/api/all"))
	}

	type Ja3 struct {
		Ja3Hash string `json:"ja3_hash"`
		Ja3     string `json:"ja3"`
	}

	opt := surf.NewOptions()
	opt.JA3().Chrome87()

	opt.ForceHTTP1()

	// opt.Proxy("http://localhost:8080")
	// opt.Proxy("socks5://localhost:9050")

	jobs, errors := surf.NewClient().SetOptions(opt).Async.Get(urls).Do()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		for job := range jobs {
			// var obj Ja3
			fmt.Println(job.Body.String())

			// job.Body.JSON(&obj)
			// fmt.Println(obj.Ja3Hash == "b32309a26951912be7dba376398abc3b")
		}
	}()

	go func() {
		defer wg.Done()

		for err := range errors {
			fmt.Println(err)
		}
	}()

	wg.Wait()

	fmt.Println("FINISH")
}
