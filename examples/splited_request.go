package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	URL := "https://httpbingo.org/get"

	cli := surf.NewClient()
	req := cli.Get(URL)

	resp, _ := req.Do()

	fmt.Println(resp.StatusCode)
	fmt.Println(resp.Body.String())
	fmt.Println(resp.Cookies)
	fmt.Println(resp.Headers)
	fmt.Println(resp.URL)
}
