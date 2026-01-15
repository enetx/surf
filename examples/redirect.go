package main

import (
	"fmt"
	"log"

	"github.com/enetx/http"
	"github.com/enetx/surf"
)

func main() {
	rp := func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return fmt.Errorf("stopped after %d redirects", 4)
		}
		return nil
	}

	cli := surf.NewClient().
		Builder().
		// MaxRedirects(4).      // max 4 redirects
		// NotFollowRedirects(). // not follow redirects
		RedirectPolicy(rp). // or custom redirect policy
		Build().
		Unwrap()

	r := cli.Get("https://httpbingo.org/redirect/6").Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().StatusCode)
}
