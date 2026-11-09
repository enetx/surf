package quic

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/enetx/quic-go/http3"
)

// NewControlGreaseFrames follows Neqo HFrame::Grease: a 57-bit type draw
// and a separate draw for a 0..7-byte payload. It is queued after SETTINGS.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/third_party/rust/neqo-http3/src/frames/hframe.rs
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/third_party/rust/neqo-http3/src/connection.rs
func NewControlGreaseFrames() ([]http3.GreaseFrame, error) {
	var draw, payload [8]byte
	if _, err := rand.Read(draw[:]); err != nil {
		return nil, err
	}

	if _, err := rand.Read(payload[:]); err != nil {
		return nil, err
	}

	n := binary.LittleEndian.Uint64(draw[:]) >> 7

	return []http3.GreaseFrame{{Type: 31*n + 33, Payload: payload[1 : 1+int(payload[0]&7)]}}, nil
}
