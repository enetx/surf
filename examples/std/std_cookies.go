package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/enetx/surf"
)

func main() {
	fmt.Println("=== Quick Cookie Test ===")

	cli := surf.NewClient().
		Builder().
		Session().
		Build().
		Unwrap()

	stdcli := cli.Std()

	// Set a cookie
	resp, _ := stdcli.Get("https://httpbin.org/cookies/set?surf=works")
	resp.Body.Close()

	// Get cookies back
	resp, _ = stdcli.Get("https://httpbin.org/cookies")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("Response: %s\n", body)

	fmt.Println("\n=== Testing Manual Cookie Setting ===")

	// Create a request with manual cookie header
	req, _ := http.NewRequest("GET", "https://httpbin.org/cookies", nil)
	req.Header.Set("Cookie", "manual_cookie=test_value; another=value2")

	resp, err := stdcli.Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("Response with manual cookies: %s\n", body)
}
