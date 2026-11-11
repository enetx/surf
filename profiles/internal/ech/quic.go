package ech

import (
	"fmt"

	"github.com/enetx/quic-go/quicvarint"
)

// PublicQUICParameters follows Neqo's filter_ch_outer. Connection identifiers,
// version negotiation, ACK timing and UDP limits remain public. Flow control
// and application capabilities are only advertised inside ECH.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/tparams.rs#L848
func PublicQUICParameters(params []byte) ([]byte, error) {
	public := make([]byte, 0, len(params))
	for len(params) > 0 {
		id, n, err := quicvarint.Parse(params)
		if err != nil {
			return nil, fmt.Errorf("ECH QUIC parameter ID: %w", err)
		}

		length, m, err := quicvarint.Parse(params[n:])
		if err != nil || length > uint64(len(params)-n-m) {
			return nil, fmt.Errorf("ECH QUIC parameter %d has invalid length", id)
		}

		end := n + m + int(length)

		switch id {
		case 0, 2, 3, 10, 11, 15, 16, 17:
			public = append(public, params[:end]...)
		}

		params = params[end:]
	}

	return public, nil
}
