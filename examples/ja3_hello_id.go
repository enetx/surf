package main

import (
	"fmt"

	"gitlab.com/x0xO/surf"
)

func main() {
	// https://github.com/lwthiker/curl-impersonate/tree/main/chrome

	url := "https://tls.peet.ws/api/all"

	opt := surf.NewOptions()
	opt.JA3().Chrome83()

	opt.ForceHTTP1()

	// opt.Proxy("socks5://localhost:9050")

	cli := surf.NewClient().SetOptions(opt)

	r, err := cli.Get(url).Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Debug().Request(true).Response(true).Print()
}
