package main

import (
	"github.com/enetx/g"
	"github.com/enetx/g/cell"
	"github.com/enetx/g/pool"
	"github.com/enetx/g/ref"
	"github.com/enetx/surf"
)

func main() {
	// Create a slice of proxy server addresses
	// SOCKS5 proxy on port 9050 (typically Tor)
	// HTTP proxy on port 2080
	proxies := g.SliceOf[g.String](
		"socks5://127.0.0.1:9050",
		"http://127.0.0.1:2080",
	)

	// Create a thread-safe cell containing a cyclic iterator over proxies
	// This allows infinite round-robin iteration through the proxy list
	guard := cell.New(ref.Of(proxies.Iter().Cycle()))

	// Build an HTTP client with custom configuration:
	cli := surf.NewClient().
		Builder().
		Singleton().            // Use a single client instance
		Impersonate().Chrome(). // Impersonate Chrome browser (spoofs User-Agent and other headers)
		Proxy(func() g.String { // Dynamic proxy selection function
			return guard.Get().Next().Some() // Get the next proxy from the cyclic iterator
		}).
		Build()

	// Defer closing idle connections when the program exits
	defer cli.CloseIdleConnections()

	// Create a slice with capacity for 10 URL strings
	urls := g.NewSlice[g.String](10)

	// Fill the entire slice with the same URL for IP checking
	// This API endpoint returns the current external IP address
	urls.Fill("https://check.torproject.org/api/ip")

	// Create a goroutine pool for parallel HTTP requests
	// Limit concurrent goroutines to 2 at a time
	p := pool.New[*surf.Response]().Limit(2)

	// Launch parallel GET requests for each URL in the pool
	for _, URL := range urls {
		p.Go(cli.Get(URL).Do) // Add task to the pool
	}

	// Wait for all requests to complete and process the results
	for r := range p.Wait().Iter() {
		switch {
		case r.IsOk(): // If the request succeeded
			// Create a map to deserialize the JSON response
			var result map[string]any

			// Parse JSON from the response body
			r.Ok().Body.JSON(&result)

			// Extract the IP address from the result
			if ip, ok := result["IP"].(string); ok {
				g.Println("IP: {}", ip) // Print the IP address
			}
		case r.IsErr(): // If an error occurred during the request
			g.Println("{}", r.Err()) // Print the error information
		}
	}
}
