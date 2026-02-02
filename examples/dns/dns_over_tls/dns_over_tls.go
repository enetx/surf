package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	r := surf.NewClient().
		Builder().
		DNSOverTLS().
		Google().
		// Switch().
		// Cloudflare().
		// LibreDNS().
		// Quad9().
		// AdGuard().
		// CIRAShield().
		// Ali().
		// Quad101().
		// SB().
		// Forge().
		// AddProvider("dns.provider.com", "0.0.0.0:853", "2.2.2.2:853"). // custom dns provider
		Build().
		Unwrap().
		Get("https://tls.peet.ws/api/all").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Body.String().Unwrap())
}
