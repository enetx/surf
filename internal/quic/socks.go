package quictransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf/pkg/quicconn"
	"github.com/wzshiming/socks5"
)

// ProxyUDPError means QUIC never reached the destination. TCP may still be
// supported by the same SOCKS proxy; cancellation keeps its original meaning.
type ProxyUDPError struct{ err error }

func (e *ProxyUDPError) Error() string { return fmt.Sprintf("SOCKS5 UDP ASSOCIATE: %v", e.err) }

func (e *ProxyUDPError) Unwrap() error { return e.err }

// dialSOCKS5 establishes a QUIC connection through a SOCKS5 proxy using UDP ASSOCIATE.
func (ut *Dialer) dialSOCKS5(
	ctx context.Context,
	resolved string,
	tlsCfg *tls.Config,
	cfg *quic.Config,
	early bool,
) (*quic.Conn, error) {
	dialer, err := socks5.NewDialer(ut.Proxy)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "udp", resolved)
	if err != nil {
		return nil, &ProxyUDPError{err: err}
	}

	success := false

	defer func() {
		if !success {
			conn.Close()
		}
	}()

	proxyUDP, err := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("resolve proxy UDP addr: %w", err)
	}

	targetUDP, err := net.ResolveUDPAddr("udp", resolved)
	if err != nil {
		return nil, fmt.Errorf("resolve target UDP addr: %w", err)
	}

	packetConn := quicconn.New(conn, proxyUDP, quicconn.EncapRaw)

	quicConn, err := ut.dialOwnedPacketConn(ctx, packetConn, targetUDP, tlsCfg, cfg, early)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	success = true

	return quicConn, nil
}
