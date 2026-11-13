package main

import (
	"fmt"
	"time"

	"github.com/enetx/surf"
)

func main() {
	// Session uses Chrome's TCP and QUIC ticket policies automatically.
	// HTTP/3 remembers server SETTINGS with each ticket. EarlyData restores those
	// limits on a new connection, while the QPACK table itself always starts empty.
	client := surf.NewClient().Builder().
		Impersonate().
		Chrome().
		Proxy("").
		Session().
		SecureTLS().
		Timeout(20 * time.Second).
		HTTP3Settings().
		EarlyData(true).
		Set().
		Build().
		Unwrap()

	defer client.Close()

	for attempt := 1; attempt <= 3; attempt++ {
		response := client.Get("https://www.cloudflare-quic.com/cdn-cgi/trace").Do().Unwrap()
		response.Body.String().Unwrap()
		fmt.Printf("attempt %d: %s, resumed=%t\n", attempt, response.Proto, response.GetResponse().TLS.DidResume)

		client.CloseIdleConnections()
	}
}

// Overrides use the same nested builder as other Surf settings. TCP and QUIC
// retain independent queues, with the selected browser defaults applied first.
func customClient() *surf.Client {
	return surf.NewClient().Builder().Impersonate().Chrome().Session().
		SessionCache().Capacity(256).
		TCP().TicketsPerKey(2).ReuseTLS12(true).
		QUIC().TicketsPerKey(2).ClearEarlyDataOnReject(true).
		Set().
		SecureTLS().Build().Unwrap()
}
