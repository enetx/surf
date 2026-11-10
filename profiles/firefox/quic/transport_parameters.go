package quic

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/transportparams"
)

// NewInitialPacketNumber follows Neqo's small common range and a
// sparse larger tail. This is browser policy; the transport accepts a factory.
func NewInitialPacketNumber() (uint64, error) {
	var data [2]byte
	if _, err := rand.Read(data[:]); err != nil {
		return 0, err
	}

	tail := 0
	if data[1] > 224 {
		tail = int(data[1]) - 224
	}

	return uint64(data[0]&31) + uint64(tail<<5) + 1, nil
}

// NewTransportParameters creates Firefox's transport parameter layout with
// fresh per-connection version GREASE and supported extension declarations.
func NewTransportParameters(version quic.Version) (*transportparams.Layout, error) {
	var data [4]byte
	if _, err := rand.Read(data[:]); err != nil {
		return nil, err
	}

	greaseVersion := (binary.BigEndian.Uint32(data[:4]) & 0xf0f0f0f0) | 0x0a0a0a0a

	info := binary.BigEndian.AppendUint32(nil, uint32(version))
	info = binary.BigEndian.AppendUint32(info, greaseVersion)

	// Neqo prefers v2, retaining a v1-compatible first flight. The engine
	// performs authenticated compatible switching before advertising this list.
	// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/version.rs
	info = binary.BigEndian.AppendUint32(info, uint32(quic.Version2))
	info = binary.BigEndian.AppendUint32(info, uint32(quic.Version1))

	// Legacy min_ack_delay is supplied by the enabled engine receiver, even
	// though the parameter shares a reserved-number residue. Keep its captured
	// position before max_datagram_frame_size.
	return &transportparams.Layout{
		DisableGrease: true,
		Order:         []uint64{1, 4, 5, 6, 7, 8, 9, 11, 14, 15, 17, 29, 0xff02de1a, 32},
		Additional:    []transportparams.Parameter{{ID: 17, Value: info}},
	}, nil
}
