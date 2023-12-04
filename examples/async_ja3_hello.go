package main

import (
	"fmt"
	"sync"

	"gitlab.com/x0xO/surf"
)

func main() {
	var urls []*surf.AsyncURL
	urls = append(urls, surf.NewAsyncURL("https://www.google.com"))
	urls = append(urls, surf.NewAsyncURL("https://ya.ru"))
	urls = append(urls, surf.NewAsyncURL("https://www.yahoo.com"))

	opt := surf.NewOptions()
	// opt.ForceHTTP1()

	opt.JA3().Chrome87()

	jobs, errors := surf.NewClient().SetOptions(opt).Async.Get(urls).Do()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		for job := range jobs {
			job.Body.Limit(20).String().Print()
			job.Debug().Request(true).Response().Print()
			// fmt.Println()
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
