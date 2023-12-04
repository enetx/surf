package main

import (
	"fmt"
	"log"
	"sync"

	"gitlab.com/x0xO/surf"
)

func main() {
	var urls []*surf.AsyncURL

	multipartData := map[string]string{
		"your-name":    "name",
		"your-message": "message",
	}

	for i := 0; i < 10; i++ {
		multipartData["number"] = fmt.Sprintf("%d", i)
		urls = append(urls, surf.NewAsyncURL("https://httpbingo.org/get").Data(multipartData))
	}

	jobs, errors := surf.NewClient().Async.Multipart(urls).Do()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		for job := range jobs {
			fmt.Println(job.Response.StatusCode)
			job.Body.Close()
		}
	}()

	go func() {
		defer wg.Done()

		for err := range errors {
			log.Println(err)
		}
	}()

	wg.Wait()

	log.Println("FINISH")
}
