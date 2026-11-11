package main

import (
	"fmt"
	"log"
	"time"

	"github.com/enetx/surf"
)

func main() {
	client := surf.NewClient().Builder().Impersonate().Windows().Firefox().
		Proxy("").Session().SecureTLS().Timeout(20 * time.Second).
		HTTP3Settings().ConnectionRacing(true).EarlyData(true).
		// Firefox already selects this policy. Eligible requests can use 0-RTT
		// while TCP preparation continues until the QUIC handshake completes.
		// Chrome selects EarlyDataBackup(false) through the same builder.
		EarlyDataBackup(true).Set().
		// Firefox also restores the initial QUIC version from its live ticket.
		QUICSettings().ResumeVersion(true).Set().Build().Unwrap()
	defer client.Close()

	for attempt := 1; attempt <= 3; attempt++ {
		result := client.Get("https://www.cloudflare-quic.com/cdn-cgi/trace").Do()
		if result.IsErr() {
			log.Fatal(result.Err())
		}
		response := result.Ok()
		body := response.Body.String()
		if body.IsErr() {
			log.Fatal(body.Err())
		}
		state := response.GetResponse().TLS
		fmt.Printf("Attempt %d: %s, resumed=%t, ECH=%t\n%s\n", attempt, response.Proto, state.DidResume, state.ECHAccepted, body.Ok())
		// The same client retains tickets and observations for a new connection.
		// The selected protocol and early-data acceptance depend on the peer.
		client.CloseIdleConnections()
	}
}
