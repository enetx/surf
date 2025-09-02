// Package quicconn provides a net.PacketConn adapter for feeding QUIC stacks
// (such as quic-go) with datagrams originating from a generic net.Conn.
//
// Typical usage is tunneling QUIC over a UDP-capable proxy (e.g. a SOCKS5 UDP
// associate). Some proxy clients expose the UDP relay as a stream-like
// net.Conn. QUIC, however, requires a net.PacketConn. This package bridges the
// gap by wrapping that net.Conn and implementing net.PacketConn on top.
//
// Two encapsulation modes are supported:
//  1. EncapRaw    — pass raw UDP payloads through; the dialer / proxy stack
//     is assumed to take care of any required encapsulation.
//  2. EncapSocks5 — add / remove RFC 1928 UDP ASSOCIATE headers on the fly,
//     so you can drive a UDP relay directly using a plain net.Conn.
//
// The adapter also exposes optional SetReadBuffer / SetWriteBuffer methods.
// quic-go detects these via type assertions and will attempt to tune socket
// buffers when available. If the underlying connection doesn't support them,
// these methods no-op and return nil. See:
// https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes
package quicconn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ErrDefaultTargetRequired is returned when a destination address is needed
// but neither an explicit addr nor defaultTarget are provided.
var ErrDefaultTargetRequired = errors.New("defaultTarget required for QUIC/UDP")

// udpEncapMode describes how UDP datagrams are encapsulated over the underlying
// net.Conn transport.
type udpEncapMode int

const (
	// EncapRaw forwards raw datagrams as-is. Use this when the component that
	// created the underlying net.Conn already handles UDP encapsulation (e.g.,
	// a SOCKS5 client that returns a UDP-capable net.Conn).
	EncapRaw udpEncapMode = iota

	// EncapSocks5 wraps outgoing datagrams in RFC 1928 UDP ASSOCIATE headers and
	// strips those headers on receive. Use this when you talk to a SOCKS5 UDP
	// relay over a plain net.Conn and need to perform the encapsulation yourself.
	EncapSocks5
)

// QuicPacketConn adapts a stream-like net.Conn into a packet-oriented
// net.PacketConn suitable for QUIC. When mode is EncapSocks5, it performs
// RFC 1928 UDP encapsulation/decapsulation on the fly.
//
// The defaultTarget is used as the destination for WriteTo when addr is nil,
// and as a fallback source address in ReadFrom when the relay doesn't expose
// a peer address.
type QuicPacketConn struct {
	conn          net.Conn
	mode          udpEncapMode
	defaultTarget *net.UDPAddr
	readBuf       []byte
	writeBuf      []byte

	rmu sync.Mutex // guards readBuf and ReadFrom
	wmu sync.Mutex // guards writeBuf and WriteTo
}

// Ensure QuicPacketConn implements net.PacketConn at compile time.
var _ net.PacketConn = (*QuicPacketConn)(nil)

// New creates a new QuicPacketConn adapter around a connected transport.
//
// Parameters:
//   - conn: a connected transport (e.g., a UDP-capable proxy connection).
//   - defaultTarget: default peer address used when WriteTo is called with addr == nil,
//     and used as a fallback source address in ReadFrom when the relay does not supply one.
//   - mode: encapsulation mode (EncapRaw or EncapSocks5).
//
// Default target requirements:
//   - EncapRaw: defaultTarget MUST be non-nil. If it is nil, New panics. In raw mode the
//     adapter cannot infer a UDP peer address from a generic net.Conn.
//   - EncapSocks5: defaultTarget may be nil because the SOCKS5 UDP header carries the peer
//     address. Providing a non-nil defaultTarget is still recommended as a fallback for
//     relays that might strip the header.
//
// The returned value implements net.PacketConn and can be passed to QUIC dialers
// (e.g., quic-go's quic.Dial).
func New(conn net.Conn, defaultTarget *net.UDPAddr, mode udpEncapMode) *QuicPacketConn {
	if defaultTarget == nil && mode == EncapRaw {
		panic("quicconn: defaultTarget is required for QUIC/UDP in EncapRaw mode")
	}

	return &QuicPacketConn{
		conn:          conn,
		mode:          mode,
		defaultTarget: defaultTarget,
		readBuf:       make([]byte, 64*1024),
		writeBuf:      make([]byte, 0, 1500),
	}
}

// SetReadBuffer optionally sets the receive buffer size if the underlying
// connection exposes such an option (e.g., *net.UDPConn or any type with
// SetReadBuffer(int) error). If unsupported, this method is a no-op and
// returns nil. quic-go probes for this method via type assertion.
func (q *QuicPacketConn) SetReadBuffer(n int) error {
	if u, ok := q.conn.(*net.UDPConn); ok {
		return u.SetReadBuffer(n)
	}

	type rb interface{ SetReadBuffer(int) error }
	if u, ok := q.conn.(rb); ok {
		return u.SetReadBuffer(n)
	}

	return nil
}

// SetWriteBuffer optionally sets the send buffer size if the underlying
// connection exposes such an option (e.g., *net.UDPConn or any type with
// SetWriteBuffer(int) error). If unsupported, this method is a no-op and
// returns nil. quic-go probes for this method via type assertion.
func (q *QuicPacketConn) SetWriteBuffer(n int) error {
	if u, ok := q.conn.(*net.UDPConn); ok {
		return u.SetWriteBuffer(n)
	}

	type wb interface{ SetWriteBuffer(int) error }
	if u, ok := q.conn.(wb); ok {
		return u.SetWriteBuffer(n)
	}

	return nil
}

// ReadFrom reads a single datagram into p and returns the number of bytes,
// the source address, and any error encountered. In EncapSocks5 mode, it
// removes the RFC 1928 header and returns the payload with decoded source
// address. If no header is present, the packet is treated as raw.
func (q *QuicPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	q.rmu.Lock()
	defer q.rmu.Unlock()

	// Calculate required readBuf size
	need := len(p)
	if q.mode == EncapSocks5 {
		// Reserve space for RFC1928 header: RSV/FRAG(3) + ATYP(1) + addr(<=16) + port(2)
		// Maximum: 3 + 1 + 16 + 2 = 22, using 32 for safety margin
		need += 32
	}

	if need > len(q.readBuf) {
		// Growth strategy: double current size or exact need, whichever is larger
		newSize := max(need, 2*len(q.readBuf))
		q.readBuf = make([]byte, newSize)
	}

	n, err := q.conn.Read(q.readBuf)
	if err != nil {
		return 0, nil, err
	}

	switch q.mode {
	case EncapSocks5:
		payload, src, ok, perr := parseSocks5UDP(q.readBuf[:n])
		if perr != nil {
			return 0, nil, perr
		}

		if !ok {
			if len(q.readBuf[:n]) > len(p) {
				return 0, nil, errors.New("buffer too small")
			}

			if q.defaultTarget == nil {
				return 0, nil, ErrDefaultTargetRequired
			}

			copy(p, q.readBuf[:n])

			return n, q.defaultTarget, nil
		}

		if len(payload) > len(p) {
			return 0, nil, errors.New("buffer too small for SOCKS5 UDP payload")
		}

		copy(p, payload)

		return len(payload), src, nil
	default: // EncapRaw
		if len(q.readBuf[:n]) > len(p) {
			return 0, nil, errors.New("buffer too small")
		}

		if q.defaultTarget == nil {
			return 0, nil, ErrDefaultTargetRequired
		}

		copy(p, q.readBuf[:n])

		return n, q.defaultTarget, nil
	}
}

// WriteTo writes datagram p to addr. If addr is nil, defaultTarget is used.
// In EncapSocks5 mode, the datagram is wrapped in an RFC 1928 UDP header.
// In EncapRaw mode, p is forwarded as-is.
func (q *QuicPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	q.wmu.Lock()
	defer q.wmu.Unlock()

	dst := q.defaultTarget
	if addr != nil {
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			return 0, errors.New("WriteTo expects *net.UDPAddr")
		}

		dst = ua
	}

	if dst == nil {
		return 0, ErrDefaultTargetRequired
	}

	if q.mode == EncapSocks5 {
		hdr, err := buildSocks5UDP(dst)
		if err != nil {
			return 0, err
		}

		// Calculate required buffer size for header + payload
		need := len(hdr) + len(p)
		if need > cap(q.writeBuf) {
			// Growth strategy: double current capacity or exact need, whichever is larger
			newCap := max(need, 2*cap(q.writeBuf))
			q.writeBuf = make([]byte, 0, newCap)
		}

		// Reuse internal buffer to avoid allocs.
		q.writeBuf = append(q.writeBuf[:0], hdr...)
		q.writeBuf = append(q.writeBuf, p...)

		n, err := q.conn.Write(q.writeBuf)
		if err != nil {
			return 0, err
		}

		if n < len(q.writeBuf) {
			return 0, io.ErrShortWrite
		}

		return len(p), nil
	}

	// EncapRaw
	n, err := q.conn.Write(p)
	if err != nil {
		return 0, err
	}

	if n < len(p) {
		return 0, io.ErrShortWrite
	}

	return len(p), nil
}

// Close closes the underlying connection.
func (q *QuicPacketConn) Close() error {
	return q.conn.Close()
}

// LocalAddr reports the local network address. It delegates to the underlying
// connection.
func (q *QuicPacketConn) LocalAddr() net.Addr {
	return q.conn.LocalAddr()
}

// SetDeadline sets both read and write deadlines on the underlying connection.
func (q *QuicPacketConn) SetDeadline(t time.Time) error {
	return q.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (q *QuicPacketConn) SetReadDeadline(t time.Time) error {
	return q.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (q *QuicPacketConn) SetWriteDeadline(t time.Time) error {
	return q.conn.SetWriteDeadline(t)
}

// buildSocks5UDP constructs an RFC 1928 UDP ASSOCIATE header for the given
// destination address. Only literal IP destinations are supported; domain
// names must be resolved by the caller.
func buildSocks5UDP(dst *net.UDPAddr) ([]byte, error) {
	if dst == nil {
		return nil, errors.New("nil destination")
	}

	h := make([]byte, 0, 4+16+2)
	h = append(h, 0x00, 0x00, 0x00) // RSV(2) + FRAG(1)

	if ip4 := dst.IP.To4(); ip4 != nil {
		h = append(h, 0x01) // ATYP = IPv4
		h = append(h, ip4...)
	} else if ip6 := dst.IP.To16(); ip6 != nil {
		h = append(h, 0x04) // ATYP = IPv6
		h = append(h, ip6...)
	} else {
		return nil, errors.New("destination IP not set")
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(dst.Port))
	h = append(h, port...)

	return h, nil
}

// parseSocks5UDP parses an RFC 1928 UDP ASSOCIATE datagram.
// It returns the payload, the decoded source address (for IPv4/IPv6 ATYP),
// a boolean indicating whether a SOCKS5 header was present, and an error.
// Domain-name ATYP on receive is not supported and results in (true, error).
func parseSocks5UDP(pkt []byte) ([]byte, net.Addr, bool, error) {
	if len(pkt) < 4 {
		return nil, nil, false, nil
	}

	if pkt[0] != 0x00 || pkt[1] != 0x00 {
		return nil, nil, false, nil
	}

	// FRAG must be 0x00 (fragmentation not supported).
	if pkt[2] != 0x00 {
		return nil, nil, true, errors.New("SOCKS5 UDP fragmentation not supported (FRAG != 0)")
	}

	atyp := pkt[3]
	off := 4

	var ip net.IP

	switch atyp {
	case 0x01: // IPv4
		if len(pkt) < off+4+2 {
			return nil, nil, true, errors.New("short IPv4 SOCKS5 UDP packet")
		}

		ip = net.IP(pkt[off : off+4])
		off += 4
	case 0x04: // IPv6
		if len(pkt) < off+16+2 {
			return nil, nil, true, errors.New("short IPv6 SOCKS5 UDP packet")
		}

		ip = net.IP(pkt[off : off+16])
		off += 16
	case 0x03: // DOMAIN
		if len(pkt) < off+1 {
			return nil, nil, true, errors.New("short domain length")
		}

		dlen := int(pkt[off])
		off++
		if len(pkt) < off+dlen+2 {
			return nil, nil, true, errors.New("short domain SOCKS5 UDP packet")
		}

		return nil, nil, true, errors.New("DOMAIN ATYP not supported on receive")
	default:
		return nil, nil, true, errors.New("unknown ATYP")
	}

	if len(pkt) < off+2 {
		return nil, nil, true, errors.New("short port")
	}

	port := int(binary.BigEndian.Uint16(pkt[off : off+2]))
	off += 2

	if len(pkt) < off {
		return nil, nil, true, errors.New("bad payload offset")
	}

	return pkt[off:], &net.UDPAddr{IP: ip, Port: port}, true, nil
}

// ConnKey computes a stable map key for a net.PacketConn, preferring the local
// address string and falling back to the pointer value. Useful for connection
// caches keyed by a PacketConn identity.
func ConnKey(pc net.PacketConn) string {
	if pc == nil {
		return "pc:nil"
	}

	if la := pc.LocalAddr(); la != nil {
		if s := la.String(); s != "" {
			return "la:" + s
		}
	}

	return fmt.Sprintf("ptr:%p", pc)
}
