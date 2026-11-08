package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/transportparams"
	"github.com/enetx/surf"
	chromequic "github.com/enetx/surf/profiles/chrome/quic"
	firefoxquic "github.com/enetx/surf/profiles/firefox/quic"
)

// Run with -profile custom, chrome or firefox. -url also accepts a local H3 server.
func main() {
	profile := flag.String("profile", "custom", "custom, chrome or firefox")
	url := flag.String("url", "https://fp.impersonate.pro/api/http3", "HTTP/3 endpoint")
	flag.Parse()

	builder := surf.NewClient().Builder()
	var config *quic.Config

	switch *profile {
	case "chrome":
		builder = builder.Impersonate().Chrome()
		config = chromequic.Config()
	case "firefox":
		builder = builder.Impersonate().Firefox()
		config = firefoxquic.Config()
	case "custom":
		config = &quic.Config{
			Versions:                       []quic.Version{quic.Version1},
			InitialStreamReceiveWindow:     1 << 20,
			MaxStreamReceiveWindow:         4 << 20,
			InitialConnectionReceiveWindow: 8 << 20,
			MaxConnectionReceiveWindow:     16 << 20,
			MaxIncomingStreams:             100,
			MaxIncomingUniStreams:          16,
			InitialPacketSize:              1250,
			DisablePathMTUDiscovery:        true,
			EnableDatagrams:                true,
		}
	default:
		log.Fatalf("unknown profile %q", *profile)
	}

	// Config() returns fresh browser defaults. QUICConfig snapshots our changes.
	config.HandshakeIdleTimeout = 10 * time.Second
	config.MaxIdleTimeout = 45 * time.Second
	settings := builder.ForceHTTP3().HTTP3Settings().QUICConfig(config)

	if *profile == "custom" {
		// TLS, transport parameters and HTTP/3 SETTINGS can be chosen independently.
		settings.ClientHelloFactory(chromequic.NewClientHelloSpec).
			ClientHandshake(&quic.ClientHandshake{
				StreamReceiveWindows: &quic.StreamReceiveWindows{
					BidiLocal: 2 << 20, BidiRemote: 1 << 20, Uni: 1 << 20,
				},
				TransportParameters: &transportparams.Layout{
					Order: []uint64{15, 1, 3, 4, 5, 6, 7, 8, 9, 14, 32, transportparams.Grease},
				},
				MaxUDPPayloadSize:            1472,
				MaxDatagramFrameSize:         65536,
				MaxAckDelay:                  25 * time.Millisecond,
				ActiveConnectionIDLimit:      4,
				InitialPacketNumber:          1,
				DisableClientHelloScrambling: true,
			}).
			ConnectionIDLength(8).
			QpackMaxTableCapacity(4096).
			QpackBlockedStreams(8).
			MaxFieldSectionSize(256 << 10).
			EnableDatagrams(true)
	}

	// These overrides also compose with the selected browser profile.
	client := settings.MaxResponseHeaderBytes(256<<10).
		StreamPriority(3, true).
		Set().Timeout(20 * time.Second).Build().Unwrap()

	defer client.Close()

	result := client.Get(g.String(*url)).Do()
	if result.IsErr() {
		log.Fatal(result.Err())
	}

	response := result.Ok()
	if response.GetResponse().ProtoMajor != 3 {
		log.Fatalf("endpoint used %s; HTTP/3 is required by this example", response.Proto)
	}

	body := response.Body.String()
	if body.IsErr() {
		log.Fatal(body.Err())
	}

	fmt.Printf("Protocol: %s\n%s\n", response.Proto, body.Ok())
}
