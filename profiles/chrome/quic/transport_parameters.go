package quic

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/transportparams"
)

// ValidatePeerTransportParameters follows QUICHE's four-byte tag vector parser
// for google_connection_options. Recognizing this format does not itself enable
// NOIP-based connection reuse, which is a separate Chromium policy setting.
// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/crypto/transport_parameters.cc
func ValidatePeerTransportParameters(parameters []transportparams.Parameter) error {
	for _, parameter := range parameters {
		if parameter.ID == 0x3128 && len(parameter.Value)%4 != 0 {
			return fmt.Errorf("invalid google_connection_options length: %d", len(parameter.Value))
		}
	}
	return nil
}

func randomQUICValue(limit uint64) (uint64, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(limit))
	if err != nil {
		return 0, err
	}

	return n.Uint64(), nil
}

// NewTransportParameters follows Chromium's randomized parameter layout.
// All browser values and GREASE policy live here, outside the QUIC fork.
func NewTransportParameters(version quic.Version) (*transportparams.Layout, error) {
	var randomVersion [4]byte
	if _, err := rand.Read(randomVersion[:]); err != nil {
		return nil, err
	}

	greaseVersion := (binary.BigEndian.Uint32(randomVersion[:]) & 0xf0f0f0f0) | 0x0a0a0a0a

	available := []uint32{uint32(version), greaseVersion}

	order, err := randomQUICValue(2)
	if err != nil {
		return nil, err
	}

	if order != 0 {
		available[0], available[1] = available[1], available[0]
	}

	information := binary.BigEndian.AppendUint32(nil, uint32(version))

	for _, v := range available {
		information = binary.BigEndian.AppendUint32(information, v)
	}

	slot, err := randomQUICValue((quicvarint.Max-27)/31 + 1)
	if err != nil {
		return nil, err
	}

	greaseID := 27 + 31*slot

	length, err := randomQUICValue(16)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, length)
	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}

	layout := &transportparams.Layout{
		DisableGrease: true,
		Additional: []transportparams.Parameter{
			{ID: 17, Value: information},
			{ID: 0x3128, Value: []byte("ORIGNOIP")},
			{ID: greaseID, Value: payload},
		},
		Order: []uint64{1, 3, 4, 5, 6, 7, 8, 9, 15, 17, 32, 0x3127, 0x3128, greaseID},
	}

	for i := len(layout.Order) - 1; i > 0; i-- {
		j, err := randomQUICValue(uint64(i + 1))
		if err != nil {
			return nil, err
		}

		layout.Order[i], layout.Order[j] = layout.Order[j], layout.Order[i]
	}

	return layout, nil
}
