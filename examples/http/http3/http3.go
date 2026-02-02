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

		// Impersonate().Firefox().HTTP3().
		Impersonate().Chrome().HTTP3().
		Build().
		Unwrap()

	// r := cli.Get("https://quic.browserleaks.com").Do()
	// r := cli.Get("https://www.cloudflare.com/cdn-cgi/trace").Do()
	r := cli.Get("https://fp.impersonate.pro/api/http3").Do()

	switch {
	case r.IsOk():
		resp := r.Ok()
		fmt.Printf("H3 Status Code: %d\n", resp.StatusCode)
		fmt.Printf("H3 Protocol: %s\n", resp.Proto)
		fmt.Printf("H3 Server: %s\n", resp.Headers.Get("server"))
		fmt.Println(r.Ok().Body.String().Unwrap())
	case r.IsErr():
		log.Printf("H3 request failed: %v", r.Err())
	}
}
