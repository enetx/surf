package main

import (
	"context"
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

type user struct {
	name    string
	age     int
	counter int
}

func main() {
	var urls []*surf.AsyncURL

	// some data
	user := user{"Edwin", 28, 0}

	for i := 0; i < 100; i++ {
		user.counter = i // change data
		urls = append(urls, surf.NewAsyncURL("https://httpbingo.org/get").Context(user))
	}

	ctx, cancel := context.WithCancel(context.Background())
	// ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	/* == URLS CHAN START == */
	urlsChan := make(chan *surf.AsyncURL)

	go func() {
		defer close(urlsChan)

		for _, URL := range urls {
			select {
			case <-ctx.Done():
				return
			default:
				urlsChan <- URL
			}
		}
	}()

	jobs, errors := surf.NewClient().
		Async.WithContext(ctx).
		Get(urlsChan).    // urls chan string
		Pool(20).         // limit concurrent connections (20)
		RateLimiter(150). // limit requests per second (150)
		Do()

	/* == URLS CHAN END == */

	// with context and pool worker, limit to 20 requests

	// jobs, errors := surf.NewClient().
	// 	Async.WithContext(ctx).
	// 	Get(urls).        // urls []string
	// 	Pool(20).         // limit concurrent connections (20)
	// 	RateLimiter(150). // limit requests per second (150)
	// 	Do()

	for jobs != nil && errors != nil {
		select {
		case job, ok := <-jobs:
			if !ok {
				jobs = nil
				continue
			}

			if job.Body.Contains("httpbingo") {
				fmt.Println(job.Context()) // get some data
				cancel()                   // stop goroutines
				log.Println("FOUND")
			}
		case err, ok := <-errors:
			if !ok {
				errors = nil
				continue
			}

			log.Println(err)
		}
	}

	// var wg sync.WaitGroup

	// wg.Add(2)

	// go func() {
	// 	defer wg.Done()
	// 	for job := range jobs {
	// 		if job.Body.Contains("google") {
	// 			fmt.Println(job.Context()) // get some data
	// 			cancel()                   // stop goroutines
	// 			log.Println("FOUND")
	// 		}
	// 	}
	// }()

	// go func() {
	// 	defer wg.Done()

	// 	for err := range errors {
	// 		log.Println(err)
	// 	}
	// }()

	// wg.Wait()

	log.Println("FINISH")
}
