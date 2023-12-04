package main

import (
	"fmt"
	"sync"

	"gitlab.com/x0xO/surf"
)

func main() {
	var urls []*surf.AsyncURL

	for i := 0; i < 10; i++ {
		urls = append(urls, surf.NewAsyncURL("https://httpbingo.org/get"))
	}

	type Get struct {
		Headers struct {
			UserAgent []string `json:"User-Agent"`
		} `json:"headers"`
	}

	opt := surf.NewOptions().UserAgent([]string{"one", "two", "three", "four", "five"})

	jobs, errors := surf.NewClient().SetOptions(opt).Async.Get(urls).Do()

	var wg sync.WaitGroup

	wg.Add(2)

	var get Get

	go func() {
		defer wg.Done()

		for job := range jobs {
			job.Body.JSON(&get)
			fmt.Println(get.Headers.UserAgent)
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
