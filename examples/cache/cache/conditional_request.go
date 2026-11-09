package main

import (
	"fmt"
	"time"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		AddHeaders("If-Modified-Since", time.Now().Format("02.01.2006-15:04:05")).
		Build().
		Unwrap().
		Get("https://httpbingo.org/cache").
		Do().
		Unwrap()

	fmt.Println(r.StatusCode)
	r.Debug().Request().Response().Print()
}
