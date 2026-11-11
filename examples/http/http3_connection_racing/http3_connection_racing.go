package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/enetx/surf"
)

func main() {
	client := surf.NewClient().Builder().Impersonate().Windows().Firefox().ForceHTTP3().
		HTTP3Settings().ConnectionRacing(true).
		// The profile selects its delay policy. Override it with this setter,
		// or use ConnectionRacingPolicy for a callback based on origin/RTT.
		TCPFallbackDelay(100 * time.Millisecond).
		Set().Timeout(15 * time.Second).Build().Unwrap()

	defer client.Close()

	// This non-replayable body is read only by the selected transport. The race
	// prepares connections, then sends one POST; it does not race two POSTs.
	result := client.Post("https://httpbin.org/post").
		StreamingBody(strings.NewReader("one streaming POST")).
		SetHeaders("Content-Type", "text/plain").Do()
	if result.IsErr() {
		log.Fatal(result.Err())
	}

	response := result.Ok()

	fmt.Printf("Selected protocol: %s\n%s\n", response.Proto, response.Body.String().Unwrap())
}
