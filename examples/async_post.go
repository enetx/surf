package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"gitlab.com/x0xO/surf"
)

func main() {
	type MultiPost struct {
		Form struct {
			Comments  []string `json:"comments"`
			Custemail []string `json:"custemail"`
			Custname  []string `json:"custname"`
		} `json:"form"`
	}

	var urls []*surf.AsyncURL

	for i := 0; i < 50; i++ {
		// note: don't forget to URL encode your query params if you use string post postData!
		// hg.HString("Hellö Wörld@Golang").Encode().URL()
		// or
		// url.QueryEscape("Hellö Wörld@Golang")
		postData := "custname=root&custtel=999999999&custemail=some@email.com" + fmt.Sprint(i)
		urls = append(urls, surf.NewAsyncURL("https://httpbingo.org/post").Data(postData))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var post MultiPost

	// with defaultMaxWorkers limited to 10 requests, no context
	// jobs, errors := surf.NewClient().Async.Post(URLs, data).Do()

	// one
	// with context and pool worker limited to 5 requests
	jobs, errors := surf.NewClient().Async.WithContext(ctx).Post(urls).Pool(5).Do()

	for jobs != nil && errors != nil {
		select {
		case job, ok := <-jobs:
			if !ok {
				jobs = nil
				continue
			}

			job.Body.JSON(&post)

			if post.Form.Custname[0] == "root" {
				fmt.Println("FOUND")
				cancel()
			}
		case err, ok := <-errors:
			if !ok {
				errors = nil
				continue
			}

			fmt.Println(err)
		}
	}

	fmt.Println(strings.Repeat("=", 80))

	// two
	// with custom pool worker limited to 100 requests
	jobs, errors = surf.NewClient().Async.Post(urls).Pool(100).Do()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		for job := range jobs {
			job.Body.JSON(&post)

			fmt.Println(post.Form.Custemail)
		}
	}()

	go func() {
		defer wg.Done()

		for err := range errors {
			fmt.Println(err)
		}
	}()

	wg.Wait()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("FINISH")
}
