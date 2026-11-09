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

	// Do not advertise compatible v2 switching: official quic-go currently only
	// supports classic version negotiation. Servers may otherwise switch keys
	// in flight, which this transport cannot process (RFC 9368).
	info = binary.BigEndian.AppendUint32(info, uint32(version))

	// The endpoint labels Firefox's 0xff02de1a as GREASE because its ID is
	// congruent to 27 modulo 31. Neqo actually uses it for legacy min_ack_delay.
	// Omit it until the transport supports that ACK_FREQUENCY draft; emitting
	// random bytes here would falsely advertise protocol support.
	return &transportparams.Layout{
		DisableGrease: true,
		Order:         []uint64{1, 4, 5, 6, 7, 8, 9, 11, 14, 15, 17, 29, 32},
		Additional:    []transportparams.Parameter{{ID: 17, Value: info}},
	}, nil
}
