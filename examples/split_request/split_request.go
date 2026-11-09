package main

import (
	"fmt"

	"github.com/enetx/surf"
)

func main() {
	cli := surf.NewClient()
	req := cli.Get("https://httpbingo.org/get")
	resp := req.Do().Unwrap()

	fmt.Println(resp.StatusCode)
	fmt.Println(resp.Body.String().Unwrap())
	fmt.Println(resp.Cookies)
	fmt.Println(resp.Headers)
	fmt.Println(resp.URL)
}
