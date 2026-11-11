package main

import (
	"fmt"
	"log"
	"time"

	"github.com/enetx/surf"
)

func main() {
	// Chrome already selects these values. The same public setters can be
	// used for a custom profile. The wire value comes from measured RTT;
	// the bounds apply only to the local initial recovery estimate.
	client := surf.NewClient().Builder().Impersonate().Windows().Chrome().
		QUICSettings().CachedInitialRTT(0x3127, 10*time.Millisecond, time.Second).
		InitialPTOMultiplier(3).Set().
		ForceHTTP3().Proxy("").Session().SecureTLS().Timeout(20 * time.Second).Build().Unwrap()

	defer client.Close()

	for attempt := 1; attempt <= 2; attempt++ {
		result := client.Get("https://fp.impersonate.pro/api/http3").Do()
		if result.IsErr() {
			log.Fatal(result.Err())
		}

		response := result.Ok()
		if response.GetResponse().ProtoMajor != 3 {
			log.Fatalf("HTTP/3 required, received %s", response.Proto)
		}

		body := response.Body.String()
		if body.IsErr() {
			log.Fatal(body.Err())
		}

		fmt.Printf("Connection %d: %s\n%s\n", attempt, response.Proto, body.Ok())
		// First connection: no history, so no RTT hint. Reuse this client
		// while opening a fresh connection to observe the learned hint.
		client.CloseIdleConnections()
	}
}
