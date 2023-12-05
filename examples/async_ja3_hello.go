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

	opt := surf.NewOptions().Impersonate().Chrome()

	cli := surf.NewClient()

	jobs, errors := cli.SetOptions(opt).Async.Get(urls).Do()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		for job := range jobs {
			job.Debug().Request(true).Response().Print()
			job.Body.Limit(2).String().Print()
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
