package main

import (
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

// ProxyRotator manages a list of proxy servers and rotates between them
type ProxyRotator struct {
	proxies g.Slice[g.String]
	index   int
}

// NewProxyRotator creates a new proxy rotator with the given proxy list
func NewProxyRotator[T ~string](proxies []T) *ProxyRotator {
	return &ProxyRotator{
		proxies: g.TransformSlice(proxies, g.NewString),
		index:   0,
	}
}

// Next returns the next proxy in rotation (round-robin)
func (pr *ProxyRotator) Next() g.String {
	if pr.proxies.Empty() {
		return ""
	}

	proxy := pr.proxies[pr.index]
	pr.index = (pr.index + 1) % len(pr.proxies)

	return proxy
}

// Random returns a random proxy from the list
func (pr *ProxyRotator) Random() g.String {
	if pr.proxies.Empty() {
		return ""
	}

	return pr.proxies.Random()
}

func main() {
	// Initialize proxy rotator with multiple proxy servers
	rotator := NewProxyRotator([]string{
		"socks5://127.0.0.1:9050", // Tor proxy
		"http://127.0.0.1:2080",   // HTTP proxy
	})

	// Example 1: Round-robin proxy rotation
	g.Println("=== Round-robin proxy rotation ===")

	client := surf.NewClient().
		Builder().
		Impersonate().Chrome().
		Proxy(rotator.Next).
		Build()

	for i := range 10 {
		g.Print("Request {}: ", i+1)

		r := client.Get("https://check.torproject.org/api/ip").Do()
		if r.IsErr() {
			g.Println("Error: {}", r.Err())
			continue
		}

		var result map[string]any
		r.Ok().Body.JSON(&result)

		if ip, ok := result["IP"].(string); ok {
			g.Println("IP: {}", ip)
		}

		time.Sleep(1 * time.Second)
	}

	// Example 2: Random proxy selection
	g.Println("\n=== Random proxy selection ===")
	client2 := surf.NewClient().
		Builder().
		Proxy(rotator.Random).
		Build()

	for i := range 10 {
		g.Print("Request {}: ", i+1)

		r := client2.Get("https://check.torproject.org/api/ip").Do()
		if r.IsErr() {
			g.Println("Error: {}", r.Err())
			continue
		}

		var result map[string]any
		r.Ok().Body.JSON(&result)

		if ip, ok := result["IP"].(string); ok {
			g.Println("IP: {}", ip)
		}

		time.Sleep(1 * time.Second)
	}
}
