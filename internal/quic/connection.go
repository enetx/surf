package quictransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/enetx/quic-go"
)

// Automatic discovery uses TCP until an alternative is advertised. Keep the
// shared UDP socket lazy, so ordinary HTTP clients don't allocate unused QUIC
// resources. Zero-length CIDs and IPv6-only paths continue to own their sockets.
func (ut *Dialer) sharedQUICTransport() (*quic.Transport, error) {
	ut.mu.Lock()
	defer ut.mu.Unlock()

	if ut.closed {
		return nil, net.ErrClosed
	}

	if ut.transport != nil {
		return ut.transport, nil
	}

	socket, err := ut.createUDPPacketConn()
	if err != nil {
		return nil, err
	}

	ut.socket = socket
	ut.transport = ut.newQUICTransport(socket)

	return ut.transport, nil
}

type ZeroConnectionIDGenerator struct{}

func (ZeroConnectionIDGenerator) ConnectionIDLen() int { return 0 }

func (ZeroConnectionIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionIDFromBytes(nil), nil
}

func (ut *Dialer) newQUICTransport(conn net.PacketConn) *quic.Transport {
	return &quic.Transport{
		Conn: conn, ConnectionIDLength: ut.ConnectionIDLength, ReceivePacketSize: ut.ReceivePacketSize,
		ConnectionIDGenerator: ut.ConnectionIDGenerator,
	}
}

// Zero-length CIDs cannot demultiplex connections on a shared socket. Proxy
// relays also own their sockets. Close each private transport with its connection.
func (ut *Dialer) dialOwnedPacketConn(
	ctx context.Context,
	packetConn net.PacketConn,
	addr net.Addr,
	tlsConfig *tls.Config,
	config *quic.Config,
	early bool,
) (*quic.Conn, error) {
	transport := ut.newQUICTransport(packetConn)
	dial := transport.Dial

	if early {
		dial = transport.DialEarly
	}

	conn, err := dial(ctx, addr, tlsConfig, config)
	if err != nil {
		transport.Close()
		packetConn.Close()

		return nil, err
	}

	go func() {
		<-conn.Context().Done()
		transport.Close()
		packetConn.Close()
	}()

	return conn, nil
}

// createUDPPacketConn creates a UDP listener, preferring IPv4.
func (ut *Dialer) createUDPPacketConn() (net.PacketConn, error) {
	if conn, err := net.ListenUDP("udp4", nil); err == nil {
		return conn, nil
	}

	return net.ListenUDP("udp6", nil)
}

// dialDirect establishes a direct QUIC connection without proxy.
func (ut *Dialer) dialDirect(
	ctx context.Context,
	resolved string,
	tlsCfg *tls.Config,
	cfg *quic.Config,
	early bool,
) (*quic.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", resolved)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP addr: %w", err)
	}

	if ut.DedicatedConn || udpAddr.IP.To4() == nil {
		var packetConn net.PacketConn
		var err error

		if udpAddr.IP.To4() == nil {
			packetConn, err = net.ListenUDP("udp6", nil)
		} else {
			packetConn, err = ut.createUDPPacketConn()
		}

		if err != nil {
			return nil, err
		}

		return ut.dialOwnedPacketConn(ctx, packetConn, udpAddr, tlsCfg, cfg, early)
	}

	transport, err := ut.sharedQUICTransport()
	if err != nil {
		return nil, err
	}

	if early {
		return transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}

	return transport.Dial(ctx, udpAddr, tlsCfg, cfg)
}

// resolve resolves a hostname to an IP address, preferring IPv4.
func (ut *Dialer) resolve(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("split host/port: %w", err)
	}

	if net.ParseIP(host) != nil {
		return addr, nil
	}

	resolver := net.DefaultResolver

	if ut.NetDialer != nil && ut.NetDialer.Resolver != nil {
		resolver = ut.NetDialer.Resolver
	}

	lookup := resolver.LookupIPAddr

	if ut.LookupIPAddr != nil {
		lookup = ut.LookupIPAddr
	}

	ips, err := lookup(ctx, host)
	if err != nil {
		return "", fmt.Errorf("DNS lookup: %w", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for %s", host)
	}

	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return net.JoinHostPort(ip.IP.String(), port), nil
		}
	}

	return net.JoinHostPort(ips[0].IP.String(), port), nil
}
