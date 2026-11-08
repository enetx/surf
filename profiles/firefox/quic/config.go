package quic

import (
	"time"

	"github.com/enetx/quic-go"
)

// Config uses Firefox 159's per-direction stream credit and connection window.
// Values belong to the Surf profile; the QUIC fork supplies only the controls.
func Config() *quic.Config {
	return &quic.Config{
		ClientHandshake: &quic.ClientHandshake{
			StreamReceiveWindows: &quic.StreamReceiveWindows{
				BidiLocal: 12 << 20, BidiRemote: 1 << 20, Uni: 1 << 20,
			},
			NewTransportParameters:       transportParameters,
			NewInitialPacketNumber:       initialPacketNumber,
			MaxUDPPayloadSize:            quic.MaxUDPReceivePacketSize,
			OmitMaxUDPPayloadSize:        true,
			MaxDatagramFrameSize:         65535,
			MaxAckDelay:                  20 * time.Millisecond,
			ActiveConnectionIDLimit:      8,
			OmitLegacyResetStreamAt:      true,
			DisableClientHelloScrambling: true,
		},
		Versions:                         []quic.Version{quic.Version1},
		HandshakeIdleTimeout:             10 * time.Second,
		MaxIdleTimeout:                   30 * time.Second,
		InitialStreamReceiveWindow:       1 << 20,
		MaxStreamReceiveWindow:           12 << 20,
		InitialConnectionReceiveWindow:   24 << 20,
		MaxConnectionReceiveWindow:       24 << 20,
		MaxIncomingStreams:               100,
		MaxIncomingUniStreams:            100,
		DisablePathMTUDiscovery:          true,
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
	}
}

// ConnectionIDLength is the browser's local source connection ID length.
const ConnectionIDLength = 3
