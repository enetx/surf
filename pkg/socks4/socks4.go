package socks4

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

const (
	socksVersion = 0x04
	socksConnect = 0x01
	socksBind    = 0x02

	accessGranted       = 0x5a
	accessRejected      = 0x5b
	accessIdentRequired = 0x5c
	accessIdentFailed   = 0x5d

	minRequestLen = 8
)

var Ident = "nobody@0.0.0.0"

func init() {
	proxy.RegisterDialerType("socks4", func(u *url.URL, d proxy.Dialer) (proxy.Dialer, error) {
		return socks4{url: u, dialer: d}, nil
	})

	proxy.RegisterDialerType("socks4a", func(u *url.URL, d proxy.Dialer) (proxy.Dialer, error) {
		return socks4{url: u, dialer: d}, nil
	})
}

type socks4 struct {
	url    *url.URL
	dialer proxy.Dialer
}

// DialContext implements proxy.ContextDialer interface
func (s socks4) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	if network != "tcp" && network != "tcp4" {
		return nil, new(ErrWrongNetwork)
	}

	// Use context-aware dialer if available
	if cd, ok := s.dialer.(proxy.ContextDialer); ok {
		c, err = cd.DialContext(ctx, network, s.url.Host)
	} else {
		c, err = s.dialer.Dial(network, s.url.Host)
	}

	if err != nil {
		return nil, &ErrDialFailed{err}
	}

	// close connection later if we got an error
	defer func() {
		if err != nil && c != nil {
			_ = c.Close()
		}
	}()

	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
		defer c.SetDeadline(time.Time{})
	}

	// Check context before handshake
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	host, port, err := s.parseAddr(addr)
	if err != nil {
		return nil, &ErrWrongAddr{addr, err}
	}

	ip := net.IPv4(0, 0, 0, 1)
	if !s.isSocks4a() {
		if ip, err = s.lookupAddr(ctx, host); err != nil {
			return nil, &ErrHostUnknown{host, err}
		}
	}

	req, err := request{Host: host, Port: port, IP: ip, Is4a: s.isSocks4a()}.Bytes()
	if err != nil {
		return nil, &ErrBuffer{err}
	}

	var i int
	i, err = c.Write(req)
	if err != nil {
		return c, &ErrIO{err}
	} else if i < minRequestLen {
		return c, &ErrIO{io.ErrShortWrite}
	}

	var resp [8]byte
	i, err = c.Read(resp[:])
	if err != nil && err != io.EOF {
		return c, &ErrIO{err}
	} else if i != 8 {
		return c, &ErrIO{io.ErrUnexpectedEOF}
	}

	switch resp[1] {
	case accessGranted:
		return c, nil
	case accessIdentRequired, accessIdentFailed:
		return c, new(ErrIdentRequired)
	case accessRejected:
		return c, new(ErrConnRejected)
	default:
		return c, &ErrInvalidResponse{resp[1]}
	}
}

// Dial implements proxy.Dialer interface
func (s socks4) Dial(network, addr string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, addr)
}

func (s socks4) lookupAddr(ctx context.Context, host string) (net.IP, error) {
	resolver := net.DefaultResolver
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return net.IP{}, err
	}

	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			return v4, nil
		}
	}

	return net.IP{}, &net.DNSError{Err: "no IPv4 address", Name: host}
}

func (s socks4) isSocks4a() bool {
	return s.url.Scheme == "socks4a"
}

func (s socks4) parseAddr(addr string) (host string, iport int, err error) {
	var port string

	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}

	iport, err = strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}

	return host, iport, err
}

type request struct {
	Host string
	Port int
	IP   net.IP
	Is4a bool

	err error
	buf bytes.Buffer
}

func (r *request) write(b []byte) {
	if r.err == nil {
		_, r.err = r.buf.Write(b)
	}
}

func (r *request) writeString(s string) {
	if r.err == nil {
		_, r.err = r.buf.WriteString(s)
	}
}

func (r *request) writeBigEndian(data any) {
	if r.err == nil {
		r.err = binary.Write(&r.buf, binary.BigEndian, data)
	}
}

func (r request) Bytes() ([]byte, error) {
	r.write([]byte{socksVersion, socksConnect})
	r.writeBigEndian(uint16(r.Port))
	r.writeBigEndian(r.IP.To4())
	r.writeString(Ident)
	r.write([]byte{0})
	if r.Is4a {
		r.writeString(r.Host)
		r.write([]byte{0})
	}

	return r.buf.Bytes(), r.err
}
