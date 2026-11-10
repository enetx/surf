package quic

import "crypto/rand"

// NewInitialDestinationConnectionIDLength follows Neqo's biased 8..20 choice.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/third_party/rust/neqo-transport/src/cid.rs
func NewInitialDestinationConnectionIDLength() (int, error) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}

	return initialDestinationConnectionIDLength(b[0]), nil
}

func initialDestinationConnectionIDLength(value byte) int {
	return max(8, 5+int(value&(value>>4)))
}
