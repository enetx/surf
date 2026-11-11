package surf

import (
	"net"

	"github.com/enetx/quic-go"
)

// Automatic discovery uses TCP until an alternative is advertised. Keep the
// shared UDP socket lazy, so ordinary HTTP clients don't allocate unused QUIC
// resources. Zero-length CIDs and IPv6-only paths continue to own their sockets.
func (ut *uquicTransport) sharedQUICTransport() (*quic.Transport, error) {
	ut.sharedMu.Lock()
	defer ut.sharedMu.Unlock()

	if ut.sharedClosed {
		return nil, net.ErrClosed
	}

	if ut.quictr != nil {
		return ut.quictr, nil
	}

	socket, err := ut.createUDPPacketConn()
	if err != nil {
		return nil, err
	}

	ut.pconn = socket
	ut.quictr = ut.newQUICTransport(socket)

	return ut.quictr, nil
}
