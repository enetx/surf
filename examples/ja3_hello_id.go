package main

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/x0xO/surf"
)

func main() {
	// https://github.com/lwthiker/curl-impersonate/tree/main/chrome

	url := "https://tls.peet.ws/api/all"

	opt := surf.NewOptions()
	opt.JA3().Chrome87()

	// opt.ForceHTTP1()

	// opt.Proxy("socks5://localhost:9050")

	cli := surf.NewClient().SetOptions(opt)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()

	r, err := cli.Get(url).WithContext(ctx).Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(r.StatusCode)
	if r.StatusCode == 101 {
		r.Body.String().Print()
	}

	r.Debug().Request(true).Response(true).Print()
}
