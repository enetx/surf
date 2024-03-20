package main

import (
	"fmt"
	"time"

	"github.com/enetx/surf"
)

func main() {
	URL := "https://httpbingo.org/cache"
	r, _ := surf.NewClient().
		Get(URL).
		AddHeaders(map[string]string{
			"If-Modified-Since": time.Now().Format("02.01.2006-15:04:05"),
		}).
		Do()

	fmt.Println(r.StatusCode)
	r.Debug().Request().Response().Print()
}
