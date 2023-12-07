package main

import (
	"log"
	"time"

	"gitlab.com/x0xO/surf"
)

func main() {
	opt := surf.NewOptions()

	opt.DNSCache(time.Second*30, 10)
	// opt.JA3().Chrome83()

	cli := surf.NewClient().SetOptions(opt) // separate client to reuse client and DNS cache
	url := "https://tls.peet.ws/api/clean"

	r, err := cli.Get(url).Do() // cache the ip of the DNS response
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		r, err = cli.Get(url).Do() // use DNS cache
		if err != nil {
			log.Fatal(err)
		}

		r.Body.String().Print()
	}

	cli.GetDNSStat().Print()
}
