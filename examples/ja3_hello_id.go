package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
)

func main() {
	// https://github.com/lwthiker/curl-impersonate/tree/main/chrome

	url := "https://tls.peet.ws/api/all"
	// url := "http://tools.scrapfly.io/api/fp/anything"

	opt := surf.NewOptions()
	// opt.ForceHTTP1()

	opt.JA3().Chrome87()

	// opt.Proxy("socks5://127.0.0.1:9050")
	// opt.Proxy("http://127.0.0.1:8080")

	cli := surf.NewClient().SetOptions(opt)

	r, err := cli.Get(url).Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Debug().Request(true).Response(true).Print()
}
