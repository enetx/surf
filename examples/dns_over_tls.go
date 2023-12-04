package main

import (
	"fmt"
	"log"

	"gitlab.com/x0xO/surf"
)

func main() {
	opt := surf.NewOptions()

	opt.DNSOverTLS().Google()
	// opt.DNSOverTLS().Switch()
	// opt.DNSOverTLS().Cloudflare()
	// opt.DNSOverTLS().LibreDNS()
	// opt.DNSOverTLS().Quad9()
	// opt.DNSOverTLS().AdGuard()
	// opt.DNSOverTLS().CIRAShield()
	// opt.DNSOverTLS().Ali()
	// opt.DNSOverTLS().Quad101()
	// opt.DNSOverTLS().SB()
	// opt.DNSOverTLS().Forge()

	// custom dns provider
	// opt.DNSOverTLS().AddProvider("dns.provider.com", "0.0.0.0:853", "2.2.2.2:853")

	r, err := surf.NewClient().SetOptions(opt).Get("https://tls.peet.ws/api/all").Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(r.Body.String())
}
