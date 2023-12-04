package main

import (
	"context"
	"fmt"
	"log"

	"gitlab.com/x0xO/http/httptrace"
	"gitlab.com/x0xO/surf"
)

func main() {
	var urls []*surf.AsyncURL

	for i := 0; i < 100; i++ {
		urls = append(urls, surf.NewAsyncURL("https://httpbingo.org/get"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	traceCtx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GetConn: func(hostPort string) { fmt.Printf("Prepare to get a connection for %s.\n", hostPort) },
		GotConn: func(info httptrace.GotConnInfo) {
			fmt.Printf(
				"Got a connection: reused: %v, from the idle pool: %v.\n",
				info.Reused,
				info.WasIdle,
			)
		},
		PutIdleConn: func(err error) {
			if err == nil {
				fmt.Println("Put a connection to the idle pool: ok.")
			} else {
				fmt.Println("Put a connection to the idle pool:", err.Error())
			}
		},
		ConnectStart: func(network, addr string) { fmt.Printf("Dialing... (%s:%s).\n", network, addr) },
		ConnectDone: func(network, addr string, err error) {
			if err == nil {
				fmt.Printf("Dial is done. (%s:%s)\n", network, addr)
			} else {
				fmt.Printf("Dial is done with error: %s. (%s:%s)\n", err, network, addr)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				fmt.Println("Wrote a request: ok.")
			} else {
				fmt.Println("Wrote a request:", info.Err.Error())
			}
		},
		GotFirstResponseByte: func() { fmt.Println("Got the first response byte.") },
	})

	jobs, errors := surf.NewClient().
		Async.WithContext(ctx). // context for async
		Get(urlsChan).          // urls chan string
		Pool(20).               // limit concurrent connections (20)
		RateLimiter(150).       // limit requests per second (150)
		WithContext(traceCtx).  // context for request, use for tracing etc...
		Do()

	for jobs != nil && errors != nil {
		select {
		case job, ok := <-jobs:
			if !ok {
				jobs = nil
				continue
			}

			if job.Body.Contains("httpbingo") {
				cancel() // stop goroutines
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

	log.Println("FINISH")
}
