package quic

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/enetx/quic-go/http3"
)

// NewControlGreaseFrames follows Quiche HttpEncoder::SerializeGreasingFrame:
// one uint32 determines both the reserved frame type and the payload length.
// Chrome 156.0.8078.79 DEPS pins this Quiche revision:
// https://github.com/chromium/chromium/blob/156.0.8078.79/DEPS
// https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/http/http_encoder.cc
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
