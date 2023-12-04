package main

import (
	"fmt"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/surf"
)

func main() {
	// https://github.com/lwthiker/curl-impersonate/tree/main/chrome

	headers := g.NewMapOrd[string, string]().
		Set(":method", "").
		Set(":authority", "").
		Set(":scheme", "").
		Set(":path", "").
		Set("sec-ch-ua", "\"Google Chrome\";v=\"87\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"87\"").
		Set("sec-ch-ua-mobile", "?0").
		Set("sec-ch-ua-platform", "\"Windows\"").
		Set("Upgrade-Insecure-Requests", "1").
		Set("User-Agent", "").
		Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").
		Set("Sec-Fetch-Site", "none").
		Set("Sec-Fetch-Mode", "navigate").
		Set("Sec-Fetch-User", "?1").
		Set("Sec-Fetch-Dest", "document").
		Set("Accept-Encoding", "gzip, deflate, br").
		Set("Accept-Language", "en-US,en;q=0.9")

	url := "https://tls.peet.ws/api/all"

	opt := surf.NewOptions()
	opt.JA3().Chrome87()
	// opt.ForceHTTP1()

	// opt.Proxy("socks5://localhost:9050")

	r, err := surf.NewClient().SetOptions(opt).Get(url).SetHeaders(headers).Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	r.Debug().Request(true).Response(true).Print()
}
