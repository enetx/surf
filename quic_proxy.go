package surf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/surf/pkg/quicconn"
	"github.com/wzshiming/socks5"
)

// proxyUDPError means QUIC never reached the destination. TCP may still be
// supported by the same SOCKS proxy; cancellation keeps its original meaning.
type proxyUDPError struct{ err error }

func (e *proxyUDPError) Error() string { return fmt.Sprintf("SOCKS5 UDP ASSOCIATE: %v", e.err) }
func (e *proxyUDPError) Unwrap() error { return e.err }

// dialSOCKS5 establishes a QUIC connection through a SOCKS5 proxy using UDP ASSOCIATE.
func (ut *uquicTransport) dialSOCKS5(
	ctx context.Context,
	resolved string,
	tlsCfg *tls.Config,
	cfg *quic.Config,
) (*quic.Conn, error) {
	dialer, err := socks5.NewDialer(ut.proxy)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "udp", resolved)
	if err != nil {
		return nil, &proxyUDPError{err: err}
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

	quicConn, err := ut.dialOwnedPacketConn(ctx, packetConn, targetUDP, tlsCfg, cfg, ut.useEarlyData(ctx))
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	success = true

	return quicConn, nil
}

// A TCP proxy bypasses local discovery, but a previously authenticated ECH
// binding must survive a routing change. An expired binding fails closed.
func (ut *uquicTransport) roundTripProxy(req *http.Request) (*http.Response, error) {
	if ut.discovery != nil && req.URL.Scheme == "https" {
		origin, err := raceAddress(req)
		if err == nil && ut.discovery.expiredECH(origin) {
			err = errHTTPSBindingExpired
		}

		if err == nil {
			if binding, ok := ut.discovery.binding(origin); ok {
				if !binding.tcp {
					err = errHTTPSNoTCP
				} else {
					route := binding.alternativeRoute
					route.tcpAddress = binding.address
					req = req.WithContext(context.WithValue(req.Context(), alternativeRouteKey{}, route))
				}
			}
		}

		if err != nil {
			if req.Body != nil {
				req.Body.Close()
			}

			return nil, err
		}
	}

	return ut.fallbackTransport.RoundTrip(req)
}
