package main

import (
	"fmt"
	"log"
	"sync"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/surf"
)

func main() {
	type Headers struct {
		Headers struct {
			Referer []string `json:"Referer"`
			Cookie  []string `json:"Cookie"`
		} `json:"headers"`
	}

	var urls []*surf.AsyncURL

	for i := 0; i < 20; i++ {
		h1 := g.NewMapOrd[string, string]().Set("Referer", "Hell: "+fmt.Sprint(i))
		h2 := map[string]string{"Referer": "Paradise: " + fmt.Sprint(i)}

		c1 := &http.Cookie{Name: "root" + fmt.Sprint(i), Value: "cookie" + fmt.Sprint(i)}
		c2 := &http.Cookie{Name: "root" + fmt.Sprint(i+100), Value: "cookie" + fmt.Sprint(i+100)}

		// build urls
		urls = append(
			urls,
			surf.NewAsyncURL("https://httpbingo.org/headers").
				SetHeaders(h1).
				AddHeaders(h2).
				AddCookies(c1, c2),
		)
	}

	jobs, errors := surf.NewClient().Async.Get(urls).Do()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		for job := range jobs {
			var headers Headers

			job.Body.JSON(&headers)

			fmt.Println(headers.Headers.Cookie, headers.Headers.Referer)
			// fmt.Println(job.Referer()) // return first only
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
