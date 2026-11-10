package quic

import (
	"fmt"
	"net"
)

// NewInitialPacketSize uses Neqo's 1280-byte starting path MTU minus IP/UDP
// headers. IPv4 and IPv6 therefore use different UDP payload sizes.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/third_party/rust/neqo-transport/src/pmtud.rs
func NewInitialPacketSize(remote net.Addr) (uint16, error) {
	addr, ok := remote.(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return 0, fmt.Errorf("QUIC packet size requires a resolved UDP address")
	}

	if addr.IP.To4() != nil {
		return 1280 - 20 - 8, nil
	}

	return 1280 - 40 - 8, nil
}
