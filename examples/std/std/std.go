package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/enetx/surf"
)

func main() {
	cli := surf.NewClient().
		Builder().
		// Proxy("socks5://127.0.0.1:1080").
		Impersonate().Firefox().
		Build().
		Unwrap()

	test(cli.Std())
}

func test(client *http.Client) {
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Printf("JA3 test failed: %v\n", err)
		return
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
