package quic

import (
	"time"

	"github.com/enetx/quic-go"
)

// Config exposes the Chromium parameters supported by official quic-go.
// Flow-control limits and empty SCIDs are pinned to Chromium 156's quic_context.cc;
// see tests/testdata/wire/README.md for sources and the remaining limitations.
func Config() *quic.Config {
	return &quic.Config{
		ClientHandshake: &quic.ClientHandshake{
			NewTransportParameters:       transportParameters,
			MaxUDPPayloadSize:            1472,
			MaxDatagramFrameSize:         65536,
			MaxAckDelay:                  25 * time.Millisecond,
			ActiveConnectionIDLimit:      2,
			InitialPacketNumber:          1,
			DisableClientHelloScrambling: true,
		},
		Versions:                       []quic.Version{quic.Version1},
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     6 << 20,
		MaxStreamReceiveWindow:         6 << 20,
		InitialConnectionReceiveWindow: 15 << 20,
		MaxConnectionReceiveWindow:     15 << 20,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          103,
		InitialPacketSize:              1250,
		DisablePathMTUDiscovery:        true,
		EnableDatagrams:                true,
	}
}

// ConnectionIDLength is the browser's local source connection ID length.
const ConnectionIDLength = 0
