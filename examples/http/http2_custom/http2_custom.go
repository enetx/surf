package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http/http2"
	"github.com/enetx/surf"
)

func main() {
	url := flag.String("url", "https://tls.peet.ws/api/all", "HTTP/2 endpoint")
	flag.Parse()

	// Start with a browser profile and override only application-specific fields.
	// A custom priority rule is an application choice, not a browser capture.
	client := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP2().
		HTTP2Settings().HpackRepresentation("x-private", surf.HPACKNeverIndex).
		ReceiveWindowUpdatePolicy(func(info surf.HTTP2ReceiveWindowUpdateInfo) bool {
			return info.Pending > info.Window/2 || info.Elapsed >= 5*time.Second
		}).
		HeaderPriority(func(req http2.PriorityRequest) http2.PriorityParam {
			weight := uint8(100)
			if strings.HasSuffix(req.URL.Path, ".css") {
				weight = 255
			}

			return http2.PriorityParam{Exclusive: true, Weight: weight}
		}).ChainStreamDependencies(true).Set().Timeout(20 * time.Second).Build().Unwrap()

	defer client.Close()

	response := client.Get(g.String(*url)).SetHeaders("x-private", "example").Do()
	if response.IsErr() {
		log.Fatal(response.Err())
	}

	defer response.Ok().Body.Close()

	body := response.Ok().Body.String()
	if body.IsErr() {
		log.Fatal(body.Err())
	}

	fmt.Printf("%s\n%s\n", response.Ok().Proto, body.Ok())
}
