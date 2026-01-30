package connectproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http2"
	_ "github.com/enetx/surf/pkg/socks4"
	"golang.org/x/net/proxy"
)

type (
	ErrProxyURL      struct{ Msg string }
	ErrProxyStatus   struct{ Msg string }
	ErrPasswordEmpty struct{ Msg string }
	ErrProxyEmpty    struct{}
)

func (e *ErrProxyURL) Error() string      { return fmt.Sprintf("bad proxy url: %s", e.Msg) }
func (e *ErrProxyStatus) Error() string   { return fmt.Sprintf("proxy response status: %s", e.Msg) }
func (e *ErrPasswordEmpty) Error() string { return fmt.Sprintf("password is empty: %s", e.Msg) }
func (e *ErrProxyEmpty) Error() string    { return "proxy is not set" }

type proxyDialer struct {
	ProxyURL      *url.URL
	DefaultHeader http.Header

	// overridden dialer allow to control establishment of TCP connection
	Dialer net.Dialer

	// DialTLSContext allows user to control establishment of TLS connection.
	// MUST return connection with completed Handshake, and NegotiatedProtocol.
	DialTLSContext func(ctx context.Context, network, address string) (net.Conn, string, error)

	h2Mu   sync.Mutex
	h2Conn *http2.ClientConn
	conn   net.Conn

	tr2Once sync.Once
	tr2     *http2.Transport
}

// SetResolver sets a custom DNS resolver for the proxy dialer.
// This resolver will be used for all DNS lookups including proxy server address
// and target host resolution. When set, target hostnames are pre-resolved locally
// before being sent to the proxy, ensuring DNS queries bypass the proxy.
func (c *proxyDialer) SetResolver(r *net.Resolver) {
	c.Dialer.Resolver = r
}

// dialerProxy is an adapter that implements proxy.Dialer interface
// using net.Dialer to support custom DNS resolver with proxies.
type dialerProxy struct {
	dialer *net.Dialer
}

func (d *dialerProxy) Dial(network, addr string) (net.Conn, error) {
	return d.dialer.Dial(network, addr)
}

func (d *dialerProxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
	socks4      = "socks4"
	socks4A     = "socks4a"
	socks5      = "socks5"
	socks5H     = "socks5h"
)

func NewDialer(proxy string) (*proxyDialer, error) {
	parsed, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}

	if parsed.Host == "" {
		return nil, &ErrProxyURL{proxy}
	}

	switch parsed.Scheme {
	case "":
		return nil, &ErrProxyURL{proxy}
	case schemeHTTP:
		if parsed.Port() == "" {
			parsed.Host = net.JoinHostPort(parsed.Host, "80")
		}
	case schemeHTTPS:
		if parsed.Port() == "" {
			parsed.Host = net.JoinHostPort(parsed.Host, "443")
		}
	case socks4, socks4A, socks5, socks5H:
		if parsed.Port() == "" {
			parsed.Host = net.JoinHostPort(parsed.Host, "1080")
		}
	default:
		return nil, &ErrProxyURL{proxy}
	}

	proxyDialer := &proxyDialer{
		ProxyURL:      parsed,
		DefaultHeader: make(http.Header),
	}

	if parsed.User != nil {
		if parsed.User.Username() != "" {
			password, ok := parsed.User.Password()
			if !ok {
				return nil, &ErrPasswordEmpty{proxy}
			}

			auth := parsed.User.Username() + ":" + password
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			proxyDialer.DefaultHeader.Add("Proxy-Authorization", basicAuth)
		}
	}

	return proxyDialer, nil
}

func (c *proxyDialer) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

type ContextKeyHeader struct{}

func (c *proxyDialer) connectHTTP1(req *http.Request, conn net.Conn) error {
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	ctx := req.Context()

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Now().Add(-time.Second))
		case <-done:
			conn.SetDeadline(time.Time{})
		}
	}()

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return err
	}

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return &ErrProxyStatus{resp.Status}
	}

	return nil
}

func (c *proxyDialer) connectHTTP2(req *http.Request, conn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	pr, pw := io.Pipe()
	req.Body = pr

	resp, err := h2clientConn.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		_ = pr.Close()
		_ = conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_ = pw.Close()
		_ = pr.Close()
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, &ErrProxyStatus{resp.Status}
	}

	return newHTTP2Conn(conn, pw, resp.Body), nil
}

func (c *proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.ProxyURL == nil {
		return nil, &ErrProxyEmpty{}
	}

	// Pre-resolve DNS locally if custom resolver is configured.
	if c.Dialer.Resolver != nil {
		host, port, err := net.SplitHostPort(address)
		if err == nil {
			if net.ParseIP(host) == nil {
				ips, err := c.Dialer.Resolver.LookupIPAddr(ctx, host)
				if err == nil && len(ips) > 0 {
					address = net.JoinHostPort(ips[0].IP.String(), port)
				}
			}
		}
	}

	if strings.HasPrefix(c.ProxyURL.Scheme, "socks") {
		forward := proxy.Dialer(&dialerProxy{dialer: &c.Dialer})

		dial, err := proxy.FromURL(c.ProxyURL, forward)
		if err != nil {
			return nil, err
		}

		return dial.(proxy.ContextDialer).DialContext(ctx, network, address)
	}

	req := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)

	maps.Copy(req.Header, c.DefaultHeader)

	if ctxHeader, ctxHasHeader := ctx.Value(ContextKeyHeader{}).(http.Header); ctxHasHeader {
		maps.Copy(req.Header, ctxHeader)
	}

	c.h2Mu.Lock()
	unlocked := false

	if c.h2Conn != nil && c.conn != nil && c.h2Conn.CanTakeNewRequest() {
		rc := c.conn
		cc := c.h2Conn
		c.h2Mu.Unlock()
		unlocked = true
		proxyConn, err := c.connectHTTP2(req, rc, cc)
		if err == nil {
			return proxyConn, nil
		}

		c.h2Mu.Lock()
		if c.conn == rc {
			c.conn = nil
			c.h2Conn = nil
		}
		c.h2Mu.Unlock()
	}

	if !unlocked {
		c.h2Mu.Unlock()
	}

	rawConn, negotiatedProtocol, err := c.initProxyConn(ctx, network)
	if err != nil {
		return nil, err
	}

	return c.connect(req, rawConn, negotiatedProtocol)
}

func (c *proxyDialer) initProxyConn(ctx context.Context, network string) (net.Conn, string, error) {
	var (
		rawConn            net.Conn
		negotiatedProtocol string
		err                error
	)

	switch c.ProxyURL.Scheme {
	case schemeHTTP:
		rawConn, err = c.Dialer.DialContext(ctx, network, c.ProxyURL.Host)
		if err != nil {
			return nil, "", err
		}
	case schemeHTTPS:
		if c.DialTLSContext != nil {
			rawConn, negotiatedProtocol, err = c.DialTLSContext(ctx, network, c.ProxyURL.Host)
			if err != nil {
				return nil, "", err
			}
		} else {
			tcpConn, err := c.Dialer.DialContext(ctx, network, c.ProxyURL.Host)
			if err != nil {
				return nil, "", err
			}

			tlsConf := tls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         c.ProxyURL.Hostname(),
				InsecureSkipVerify: true,
			}

			tlsConn := tls.Client(tcpConn, &tlsConf)

			if err = tlsConn.HandshakeContext(ctx); err != nil {
				_ = tcpConn.Close()
				return nil, "", err
			}

			negotiatedProtocol = tlsConn.ConnectionState().NegotiatedProtocol
			rawConn = tlsConn
		}
	default:
		return nil, "", &ErrProxyURL{c.ProxyURL.String()}
	}

	return rawConn, negotiatedProtocol, err
}

func (c *proxyDialer) connect(req *http.Request, conn net.Conn, negotiatedProtocol string) (net.Conn, error) {
	if negotiatedProtocol == http2.NextProtoTLS {
		c.tr2Once.Do(func() { c.tr2 = new(http2.Transport) })

		h2clientConn, err := c.tr2.NewClientConn(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}

		proxyConn, err := c.connectHTTP2(req, conn, h2clientConn)
		if err != nil {
			return nil, err
		}

		c.h2Mu.Lock()
		c.h2Conn = h2clientConn
		c.conn = conn
		c.h2Mu.Unlock()

		return proxyConn, nil
	}

	if err := c.connectHTTP1(req, conn); err != nil {
		return nil, err
	}

	return conn, nil
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Close() error {
	err1 := h.in.Close()
	err2 := h.out.Close()
	return errors.Join(err1, err2)
}

func (h *http2Conn) Read(p []byte) (n int, err error)  { return h.out.Read(p) }
func (h *http2Conn) Write(p []byte) (n int, err error) { return h.in.Write(p) }
func (h *http2Conn) CloseConn() error                  { return h.Conn.Close() }
func (h *http2Conn) CloseWrite() error                 { return h.in.Close() }
func (h *http2Conn) CloseRead() error                  { return h.out.Close() }
