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
)

// Run with -profile custom, chrome or firefox. -url also accepts a local H3 server.
func main() {
	profile := flag.String("profile", "custom", "custom, chrome or firefox")
	url := flag.String("url", "https://fp.impersonate.pro/api/http3", "HTTP/3 endpoint")
	flag.Parse()

	builder := surf.NewClient().Builder()
	switch *profile {
	case "chrome":
		builder = builder.Impersonate().Chrome()
	case "firefox":
		builder = builder.Impersonate().Firefox()
	case "custom":
	default:
		log.Fatalf("unknown profile %q", *profile)
	}

	// Each setter overrides one option and keeps the rest of the browser profile.
	quicSettings := builder.ForceHTTP3().QUICSettings().
		HandshakeIdleTimeout(10 * time.Second).
		MaxIdleTimeout(45 * time.Second)

	if *profile == "custom" {
		// TLS, transport parameters and HTTP/3 SETTINGS can be chosen independently.
		quicSettings.Versions(quic.Version1).
			InitialStreamReceiveWindow(1<<20).
			MaxStreamReceiveWindow(4<<20).
			InitialConnectionReceiveWindow(8<<20).
			MaxConnectionReceiveWindow(16<<20).
			MaxIncomingStreams(100).
			MaxIncomingUniStreams(16).
			InitialPacketSize(1250).
			DisablePathMTUDiscovery(true).
			ClientHelloFactory(chromequic.NewClientHelloSpec).
			StreamReceiveWindows(2<<20, 1<<20, 1<<20).
			TransportParameterOrder(15, 1, 3, 4, 5, 6, 7, 8, 9, 14, 32, transportparams.Grease).
			MaxUDPPayloadSize(1472).
			MaxDatagramFrameSize(65536).
			MaxAckDelay(25*time.Millisecond).
			InitialCongestionWindowPackets(10).
			// Receiving peer requests and requesting the peer's ACK rate are independent.
			LegacyAckFrequency(time.Millisecond).
			PeerAckFrequencyPolicy(func(info surf.PeerAckFrequencyInfo) (surf.PeerAckFrequency, bool) {
				target := surf.PeerAckFrequency{
					AckElicitingThreshold: 4,
					MaxAckDelay:           max(info.PeerMinAckDelay, 2*time.Millisecond),
				}
				return target, target != info.Current
			}).
			AckPacketThreshold(2).
			AckDecimation(100, 10).
			AckDelayRTTDivisor(4).
			MinAckDelay(time.Millisecond).
			AckReordering(surf.AckReorderingWindow).
			AckMissingPacketLimit(4).
			AckECN(surf.AckECNTransitions).
			ActiveConnectionIDLimit(4).
			InitialDestinationConnectionIDLength(8).
			InitialCryptoFrameSplits(2, 10).
			InitialPingFrames(2, 10).
			InitialCryptoFirstFrameSize(55, 86).
			ReceiveWindowUpdateDivisor(2).
			AckOnlyPingThreshold(-1).
			AckOnlyMaxDataThreshold(19).
			OmitInitialAckOnHandshake(true).
			DisableConnectionIDRotation(true).
			InitialPacketNumber(1).
			DisableClientHelloScrambling(true).
			ConnectionIDLength(8).
			EnableDatagrams(true)
	}

	settings := quicSettings.Set().HTTP3Settings()
	if *profile == "custom" {
		settings.CoalesceInitialSettings(true).QpackMaxTableCapacity(4096).
			QpackDynamicTable(true).
			QpackHuffman(surf.QPACKHuffmanAuto).
			QpackIndexing(surf.QPACKIndexAll).
			QpackIndexingPolicy(func(name, value string) bool { return name != "x-transient" }).
			QpackDrainingFraction(.25).
			QpackPostBaseReferences(false).
			QpackLiteralInsertNames(false).
			QpackStopOnInsertionFailure(false).
			QpackMaxTrackedSections(256).
			QpackEncoderZeroCapacity(true).
			QpackBlockedStreams(8).
			QpackStreamOrder(surf.QPACKDecoderStream, surf.QPACKEncoderStream).
			QpackEagerStreamTypes(false).
			QpackEncoderTableCapacity(4096).
			QpackEncoderCapacityTiming(surf.QPACKCapacityBeforeHeaders).
			// These are custom policy choices; browser profiles configure their
			// own cookie splitting, initial priority updates and control GREASE.
			QpackSplitCookies(true).
			QpackNeverIndex("cookie", "authorization").
			PriorityUpdates(true).
			CompactPriorityUpdates(false).
			RequestBodyBufferSize(32 << 10).
			MaxDataFrameSize(16 << 10).
			Grease().
			ControlGreaseFrames(surf.HTTP3GreaseFrame{Type: 33, Payload: []byte("custom")}).
			RequestGreaseFrames(surf.HTTP3GreaseFrame{Type: 64}).
			MaxFieldSectionSize(256 << 10)
	}

	// These overrides also compose with the selected browser profile.
	client := settings.MaxResponseHeaderBytes(256<<10).
		StreamPriority(3, true).
		Set().Timeout(20 * time.Second).Build().Unwrap()

	defer client.Close()

	// This explicit update changes the peer's response priority. Retain the
	// updater to make later changes while the response is open; return promptly.
	result := client.Get(g.String(*url)).HTTP3PriorityUpdates(func(priority *surf.HTTP3PriorityUpdater) {
		if err := priority.Update(1, true); err != nil {
			log.Printf("priority update: %v", err)
		}
	}).Do()
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
