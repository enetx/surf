package main

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/surf"
)

func main() {
	start := time.Now()
	urlsChan := make(chan *surf.AsyncURL)

	file := g.NewFile("domains.txt")

	go func() {
		defer close(urlsChan)

		for line := file.Iterator().Unwrap().ByLines(); line.Next(); {
			urlsChan <- surf.NewAsyncURL("http://" + line.ToString().TrimSpace().Std())
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opt := surf.NewOptions().
		DisableKeepAlive().
		MaxRedirects(3).
		Timeout(time.Second * 20).
		ForceHTTP1().
		GetRemoteAddress().
		DNS("127.0.0.1:53")

	jobs, errors := surf.NewClient().
		SetOptions(opt).
		Async.WithContext(ctx).
		Get(urlsChan).
		Pool(100).
		Do()

	const limitBytes = 250000

	var counter int32
	for jobs != nil && errors != nil {
		atomic.AddInt32(&counter, 1)

		if counter%1000 == 0 {
			fmt.Printf(
				"number goroutines: %d started at: %s now: %s, urls counter: %d\n\n",
				runtime.NumGoroutine(),
				start.Format("2006-01-02 15:04:05"),
				time.Now().Format("2006-01-02 15:04:05"),
				counter,
			)
		}

		select {
		case job, ok := <-jobs:
			if !ok {
				jobs = nil
				continue
			}

			job.Body.Limit(limitBytes).Bytes()
			fmt.Println(job.RemoteAddress())
			// job.Body.Bytes()
		case _, ok := <-errors:
			if !ok {
				errors = nil
				continue
			}
		}
	}
}
