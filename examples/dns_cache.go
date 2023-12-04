package main

import (
	"fmt"
	"log"
	"time"

	"gitlab.com/x0xO/surf"
)

func main() {
	opt := surf.NewOptions()

	opt.DNSCache(time.Second*30, 10)
	opt.JA3().Chrome83()

	cli := surf.NewClient().SetOptions(opt) // separate client to reuse client and DNS cache
	url := "https://tls.peet.ws/api/all"

	r, err := cli.Get(url).Do() // cache the ip of the DNS response

	for i := 0; i < 10; i++ {
		r, err = cli.Get(url).Do() // use DNS cache
		fmt.Println(r.Body.String())
	}

	if err != nil {
		log.Fatal(err)
	}

	cli.ClearCachedTransports()

	r.Debug().DNSStat().Print()
}
