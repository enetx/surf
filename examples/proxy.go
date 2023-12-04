package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	type Proxy struct {
		ISTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}

	URL := "https://check.torproject.org/api/ip"

	// for random select proxy from slice
	r, err := surf.NewClient().
		SetOptions(surf.NewOptions().Proxy([]string{
			"socks5://127.0.0.1:9050",
			"socks5://127.0.0.1:9050",
		})).
		Get(URL).
		Do()
		// r, err := surf.NewClient().
		// 	SetOptions(surf.NewOptions().Proxy("http://127.0.0.1:8080")).
		// 	Get(URL).
		// 	Do()
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Println(r.Body)

	var proxy Proxy

	r.Body.JSON(&proxy)

	fmt.Printf("is tor: %v, ip: %s", proxy.ISTor, proxy.IP)
}
