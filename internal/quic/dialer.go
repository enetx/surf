// Package quictransport owns UDP sockets and QUIC connection establishment.
package quictransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/enetx/quic-go"
)

// Dialer owns UDP sockets and QUIC connection attempts for one HTTP/3 transport.
// NetDialer preserves the client's resolver pointer; configuration is set before use.
type Dialer struct {
	mu                    sync.Mutex
	closed                bool
	transport             *quic.Transport
	socket                net.PacketConn
	NetDialer             *net.Dialer
	Proxy                 string
	Lazy                  bool
	ResolveAll            bool
	AddressFallbackDelay  time.Duration
	ReceivePacketSize     int
	ConnectionIDLength    int
	ConnectionIDGenerator quic.ConnectionIDGenerator
	DedicatedConn         bool
}

// Init opens a shared UDP socket unless ownership is lazy or per connection.
func (ut *Dialer) Init() error {
	if ut.Proxy == "" && !ut.DedicatedConn && !ut.Lazy {
		var err error
		ut.socket, err = ut.createUDPPacketConn()
		if err != nil {
			return fmt.Errorf("create packet conn: %w", err)
		}
		ut.transport = ut.newQUICTransport(ut.socket)
	}
	return nil
}

// Dial completes the handshake before exposing the connection.
func (ut *Dialer) Dial(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config, hints []netip.Addr) (*quic.Conn, error) {
	return ut.dial(ctx, address, tlsConfig, config, hints, false)
}

// DialEarly allows resumable connections to carry eligible early application data.
func (ut *Dialer) DialEarly(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config, hints []netip.Addr) (*quic.Conn, error) {
	return ut.dial(ctx, address, tlsConfig, config, hints, true)
}

func (ut *Dialer) dial(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config, hints []netip.Addr, early bool) (*quic.Conn, error) {
	if ut.ResolveAll || ut.AddressFallbackDelay > 0 {
		addresses, err := ut.resolveAddresses(ctx, address, hints)
		if err != nil {
			return nil, err
		}
		return ut.dialAddresses(ctx, addresses, tlsConfig, config, early)
	}
	resolved, err := ut.resolve(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution: %w", err)
	}
	if ut.Proxy != "" {
		return ut.dialSOCKS5(ctx, resolved, tlsConfig, config, early)
	}
	return ut.dialDirect(ctx, resolved, tlsConfig, config, early)
}

// Close releases the shared UDP transport. HTTP/3 owns application connections.
func (ut *Dialer) Close() {
	ut.mu.Lock()
	ut.closed = true
	transport, socket := ut.transport, ut.socket
	ut.mu.Unlock()
	if transport != nil {
		transport.Close()
	}
	if socket != nil {
		socket.Close()
	}
}
