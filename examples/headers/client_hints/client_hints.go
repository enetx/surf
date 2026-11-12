package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
)

func main() {
	// HTTP loopback is a trustworthy origin for Chromium Client Hints. This
	// self-contained peer requests metadata without depending on a public service.
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(header.ACCEPT_CH, "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Platform-Version")
		w.Header().Set(header.CRITICAL_CH, "Sec-CH-UA-Arch")
		w.Header().Set(header.CONTENT_TYPE, "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			header.SEC_CH_UA_ARCH:             r.Header.Get(header.SEC_CH_UA_ARCH),
			header.SEC_CH_UA_BITNESS:          r.Header.Get(header.SEC_CH_UA_BITNESS),
			header.SEC_CH_UA_PLATFORM_VERSION: r.Header.Get(header.SEC_CH_UA_PLATFORM_VERSION),
		})
	}))

	defer peer.Close()

	client := surf.NewClient().Builder().
		Proxy("").
		Impersonate().Chrome().
		ClientHints().Architecture("x86").Bitness("64").PlatformVersion("19.0.0").Set().
		Build().
		Unwrap()

	defer client.Close()

	// Chrome profiles enable negotiation automatically; ClientHints is only needed
	// to override identity or cache settings. The first navigation is restarted
	// once when the server requests a missing critical hint. The next navigation
	// sends remembered hints immediately. Ordinary POST/fetch responses do not opt in.
	for range 2 {
		result := client.Get(g.String(peer.URL)).Do()
		if result.IsErr() {
			fmt.Println(result.Err())
			return
		}

		fmt.Println(result.Ok().Body.String().Unwrap())
	}

	fmt.Println("Learned:", client.ClientHintNames(g.String(peer.URL)))

	client.ClearClientHints()
}
