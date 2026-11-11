package quic

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/enetx/quic-go/http3"
)

// NewControlGreaseFrames follows Quiche HttpEncoder::SerializeGreasingFrame:
// one uint32 determines both the reserved frame type and the payload length.
// Chrome 157.0.8103.51 DEPS pins this Quiche revision:
// https://github.com/chromium/chromium/blob/157.0.8103.51/DEPS
// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/http/http_encoder.cc
func NewControlGreaseFrames() ([]http3.GreaseFrame, error) {
	var draw [4]byte
	if _, err := rand.Read(draw[:]); err != nil {
		return nil, err
	}

	n := binary.LittleEndian.Uint32(draw[:])
	payload := make([]byte, n%4)

	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}

	return []http3.GreaseFrame{{Type: 0x1f*uint64(n) + 0x21, Payload: payload}}, nil
}

// NewSettingsGrease follows QuicSendControlStream::MaybeSendSettingsFrame:
// two independent uint32 draws select the reserved identifier and its value.
// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/http/quic_send_control_stream.cc
func NewSettingsGrease() (uint64, uint64, error) {
	var draws [8]byte
	if _, err := rand.Read(draws[:]); err != nil {
		return 0, 0, err
	}

	return 0x1f*uint64(binary.LittleEndian.Uint32(draws[:4])) + 0x21, uint64(binary.LittleEndian.Uint32(draws[4:])), nil
}
