package main

import (
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	builder := surf.NewClient().Builder().Impersonate().Chrome()
	// builder := surf.NewClient().Builder().Impersonate().Firefox()
	// builder.ForceHTTP3() // Require QUIC instead of automatic protocol selection.

	// The profile supplies the browser's inner ClientHello policy. Discovery
	// obtains ECHConfig from HTTPS DNS records using the client's DNS settings.
	// This example keeps certificate verification enabled.
	client := builder.SecureTLS().Build().Unwrap()
	defer client.Close()

	// This host advertises ECH and h3 in its HTTPS record at the time of writing.
	// www.cloudflare.com currently advertises h3 but no ECHConfig.
	result := client.Get("https://www.cloudflare-quic.com/cdn-cgi/trace").Do()
	if result.IsErr() {
		log.Fatal(result.Err())
	}

	response := result.Ok()

	state := response.GetResponse().TLS
	if state == nil {
		log.Fatal("response has no TLS state")
	}

	fmt.Printf("Protocol: %s\nECH accepted: %t\n", response.Proto, state.ECHAccepted)
	// False can mean that DNS supplied no usable ECHConfig, or that a configured
	// proxy bypassed local HTTPS discovery. The browser profile alone is not
	// evidence of real ECH. Rejected real ECH returns an error instead of silently
	// retrying with an unencrypted ClientHello.

	body := response.Body.String()
	if body.IsErr() {
		log.Fatal(body.Err())
	}

	fmt.Println(body.Ok())
}
