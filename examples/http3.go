package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	fmt.Println("=== HTTP/3 Example ===")
	cli := surf.NewClient().Builder().
		// DNS("127.0.0.1:53").
		// DNS("1.1.1.1:53").
		// Proxy("socks5://127.0.0.1:1080"). // dante
		// Proxy("socks5h://127.0.0.1:2080").
		// Proxy("http://127.0.0.1:2080").
		Impersonate().Firefox().HTTP3().
		Build()

	// r := cli.Get("https://cloudflare-quic.com").Do()
	r := cli.Get("https://fp.impersonate.pro/api/http3").Do()

	switch {
	case r.IsOk():
		resp := r.Ok()
		fmt.Printf("Chrome H3 Status Code: %d\n", resp.StatusCode)
		fmt.Printf("Chrome H3 Protocol: %s\n", resp.Proto)
		fmt.Printf("Chrome H3 Server: %s\n", resp.Headers.Get("server"))
		fmt.Println(r.Ok().Body.String())
	case r.IsErr():
		log.Printf("Chrome H3 request failed: %v", r.Err())
	}

	// "perk_text": "1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p",
	// "perk_hash": "e1d11ee6f2f4c7b1f11bfaaf4dbbc211",
}
