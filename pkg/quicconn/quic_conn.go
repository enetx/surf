package quicconn

import (
	"io"
	"net"
	"sync"
	"time"
)

// QuicPacketConn is a net.PacketConn adapter over a connected UDP relay (e.g., a SOCKS5
// UDP associate tunnel created by wzshiming/socks5). The relay itself performs the SOCKS5
// UDP encapsulation/decapsulation, so this adapter passes raw datagrams through as-is.
// It maintains a best-effort "remote" address used for QUIC path semantics.
type QuicPacketConn struct {
	conn       net.Conn
	remoteAddr net.Addr
	mu         sync.RWMutex
}

// Compile-time interface assertion.
var _ net.PacketConn = (*QuicPacketConn)(nil)

// New returns a PacketConn that forwards raw datagrams over the provided
// connected UDP relay. The remoteAddr is used as the initial peer address returned
// from ReadFrom and as a fallback when the relay does not expose the real peer address.
func New(conn net.Conn, remoteAddr net.Addr) net.PacketConn {
	return &QuicPacketConn{conn: conn, remoteAddr: remoteAddr}
}

// ReadFrom reads a single datagram from the relay into p. It attributes the packet
// to the last known peer address (if any), or to the relay's remote address as a fallback.
// It returns the number of bytes copied into p, the attributed source address, and an error, if any.
func (q *QuicPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := q.conn.Read(p)
	return n, q.remoteAddrOrRelay(), err
}

// WriteTo writes the datagram p to the relay. If addr is non-nil, it becomes the new
// best-known peer address, used for subsequent ReadFrom attributions and QUIC path semantics.
// The relay handles any required UDP encapsulation; p must be the raw payload.
func (q *QuicPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if ua, ok := addr.(*net.UDPAddr); ok && ua != nil {
		q.mu.Lock()
		q.remoteAddr = ua
		q.mu.Unlock()
	}

	n, err := q.conn.Write(p)
	if err != nil {
		return 0, err
	}

	if n != len(p) {
		return 0, io.ErrShortWrite
	}

	return n, nil
}

// remoteAddrOrRelay returns the best-known peer address if available, otherwise
// the relay's remote address. This is used to attribute datagrams for QUIC path logic.
func (q *QuicPacketConn) remoteAddrOrRelay() net.Addr {
	q.mu.RLock()
	ra := q.remoteAddr
	q.mu.RUnlock()

	if ra != nil {
		return ra
	}

	return q.conn.RemoteAddr()
}

// Close closes the underlying relay connection.
func (q *QuicPacketConn) Close() error { return q.conn.Close() }

// LocalAddr returns the local address of the underlying relay connection.
func (q *QuicPacketConn) LocalAddr() net.Addr { return q.conn.LocalAddr() }

// SetDeadline sets both read and write deadlines on the underlying relay connection.
func (q *QuicPacketConn) SetDeadline(t time.Time) error { return q.conn.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the underlying relay connection.
func (q *QuicPacketConn) SetReadDeadline(t time.Time) error { return q.conn.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the underlying relay connection.
func (q *QuicPacketConn) SetWriteDeadline(t time.Time) error {
	return q.conn.SetWriteDeadline(t)
}

// SetReadBuffer attempts to configure the UDP read buffer size on the underlying
// connection if it exposes such an option (e.g., *net.UDPConn). It is a best-effort
// operation and returns nil when unsupported.
func (q *QuicPacketConn) SetReadBuffer(n int) error {
	if u, ok := q.conn.(*net.UDPConn); ok {
		return u.SetReadBuffer(n)
	}

	// Optional: support other conns that expose SetReadBuffer(int) error
	type rb interface{ SetReadBuffer(int) error }
	if u, ok := q.conn.(rb); ok {
		return u.SetReadBuffer(n)
	}

	return nil
}

// SetWriteBuffer attempts to configure the UDP write buffer size on the underlying
// connection if it exposes such an option (e.g., *net.UDPConn). It is a best-effort
// operation and returns nil when unsupported.
func (q *QuicPacketConn) SetWriteBuffer(n int) error {
	if u, ok := q.conn.(*net.UDPConn); ok {
		return u.SetWriteBuffer(n)
	}

	// Optional: support other conns that expose SetWriteBuffer(int) error
	type wb interface{ SetWriteBuffer(int) error }
	if u, ok := q.conn.(wb); ok {
		return u.SetWriteBuffer(n)
	}

	return nil
}
