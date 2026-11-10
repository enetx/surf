package main

import (
	"fmt"
	"log"
	"time"

	"github.com/enetx/surf"
)

func main() {
	client := surf.NewClient().Builder().Impersonate().Windows().Chrome().
		HTTP3Settings().Discovery(true).Set().SecureTLS().Timeout(20 * time.Second).Build().Unwrap()
	defer client.Close()

	// Discovery authenticates advertisements and prepares connections without
	// sending an extra application request. Each iteration is a separate GET.
	for attempt := 1; attempt <= 4; attempt++ {
		result := client.Get("https://fp.impersonate.pro/api/http3").Do()
		if result.IsErr() {
			log.Fatal(result.Err())
		}
		response := result.Unwrap()
		body := response.Body.String()
		if body.IsErr() {
			log.Fatal(body.Err())
		}
		fmt.Printf("Request %d: %s\n", attempt, response.Proto)
		if response.GetResponse().ProtoMajor == 3 {
			fmt.Println(body.Unwrap())
			return
		}
		// A TCP winner can leave a connection-only QUIC attempt warming.
		time.Sleep(150 * time.Millisecond)
	}
	log.Print("HTTP/3 was not advertised or did not become available; requests used TCP")
}
