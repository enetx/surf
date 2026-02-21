package surf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/url"
	"syscall"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http3"
	"github.com/enetx/surf/pkg/quicconn"
	"github.com/quic-go/quic-go"
	"github.com/wzshiming/socks5"
)

// HTTP/3 SETTINGS frame parameter identifiers as defined in RFC 9114.
const (
	SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01
	SETTINGS_MAX_FIELD_SECTION_SIZE   = 0x06
	SETTINGS_QPACK_BLOCKED_STREAMS    = 0x07
	SETTINGS_ENABLE_CONNECT_PROTOCOL  = 0x08
	SETTINGS_H3_DATAGRAM              = 0x33
	H3_DATAGRAM                       = 0xFFD277
	SETTINGS_ENABLE_WEBTRANSPORT      = 0x2B603742
)

// HTTP3Settings provides a fluent interface for configuring HTTP/3 SETTINGS parameters.
// These settings are sent to the server during connection establishment.
type HTTP3Settings struct {
	builder  *Builder
	settings g.MapOrd[uint64, uint64]
}

// QpackMaxTableCapacity sets the maximum dynamic table capacity for QPACK.
func (h *HTTP3Settings) QpackMaxTableCapacity(num uint64) *HTTP3Settings {
	h.settings.Insert(SETTINGS_QPACK_MAX_TABLE_CAPACITY, num)
	return h
}

// MaxFieldSectionSize sets the maximum size of a field section the peer is willing to accept.
func (h *HTTP3Settings) MaxFieldSectionSize(num uint64) *HTTP3Settings {
	h.settings.Insert(SETTINGS_MAX_FIELD_SECTION_SIZE, num)
	return h
}

// QpackBlockedStreams sets the maximum number of streams that can be blocked on QPACK.
func (h *HTTP3Settings) QpackBlockedStreams(num uint64) *HTTP3Settings {
	h.settings.Insert(SETTINGS_QPACK_BLOCKED_STREAMS, num)
	return h
}

// EnableConnectProtocol enables the extended CONNECT protocol (RFC 9220).
func (h *HTTP3Settings) EnableConnectProtocol(num uint64) *HTTP3Settings {
	h.settings.Insert(SETTINGS_ENABLE_CONNECT_PROTOCOL, num)
	return h
}

// SettingsH3Datagram sets the H3_DATAGRAM setting value.
func (h *HTTP3Settings) SettingsH3Datagram(num uint64) *HTTP3Settings {
	h.settings.Insert(SETTINGS_H3_DATAGRAM, num)
	return h
}

// H3Datagram sets a custom H3_DATAGRAM value for datagram support.
func (h *HTTP3Settings) H3Datagram(num uint64) *HTTP3Settings {
	h.settings.Insert(H3_DATAGRAM, num)
	return h
}

// EnableWebtransport enables WebTransport support over HTTP/3.
func (h *HTTP3Settings) EnableWebtransport(num uint64) *HTTP3Settings {
	h.settings.Insert(SETTINGS_ENABLE_WEBTRANSPORT, num)
	return h
}

// Grease adds a GREASE parameter with random ID and value to prevent protocol ossification.
func (h *HTTP3Settings) Grease() *HTTP3Settings {
	maxn := (uint64(1<<62) - 1 - 0x21) / 0x1F
	n := uint64(rand.Uint32()) % maxn
	h.settings.Insert(0x1F*n+0x21, uint64(rand.Uint32()))

	return h
}

// Set applies the configured HTTP/3 settings to the client's transport.
func (h *HTTP3Settings) Set() *Builder {
	return h.builder.addCliMW(func(c *Client) error {
		if h.builder.forceHTTP1 || h.builder.forceHTTP2 || !h.builder.http3 {
			return nil
		}

		transport, err := newUQUICTransport(h.settings, c, h.builder)
		if err != nil {
			return err
		}

		c.GetClient().Transport = transport
		c.transport = transport

		return nil
	}, math.MaxInt-1)
}

// uquicTransport implements http.RoundTripper with HTTP/3 support.
// It provides SOCKS5 proxy compatibility and automatic fallback to HTTP/2
// when HTTP/3 is unavailable or for non-SOCKS5 proxies.
type uquicTransport struct {
	http3tr           *http3.Transport
	quictr            *quic.Transport
	pconn             net.PacketConn
	fallbackTransport http.RoundTripper
	tlsConfig         *tls.Config
	dialer            *net.Dialer
	settings          g.MapOrd[uint64, uint64]
	proxy             string
}

// newUQUICTransport creates a new HTTP/3 transport with the given settings.
func newUQUICTransport(settings g.MapOrd[uint64, uint64], c *Client, builder *Builder) (*uquicTransport, error) {
	ut := &uquicTransport{
		tlsConfig: c.tlsConfig.Clone(),
		dialer:    c.GetDialer(),
		settings:  settings,
		proxy:     builder.proxy.Std(),
	}

	if !builder.forceHTTP3 {
		ut.fallbackTransport = c.GetTransport()
	}

	if ut.proxy != "" && !isSOCKS5Proxy(ut.proxy) {
		if ut.fallbackTransport == nil {
			return nil, errors.New("HTTP/3 requires SOCKS5 proxy for UDP relay")
		}
		return ut, nil
	}

	if err := ut.initTransport(); err != nil {
		return nil, err
	}

	return ut, nil
}

// initTransport initializes the underlying QUIC and HTTP/3 transports.
func (ut *uquicTransport) initTransport() error {
	if ut.proxy == "" {
		var err error
		ut.pconn, err = ut.createUDPPacketConn()
		if err != nil {
			return fmt.Errorf("create packet conn: %w", err)
		}

		ut.quictr = &quic.Transport{Conn: ut.pconn}
	}

	ut.http3tr = &http3.Transport{
		TLSClientConfig: ut.tlsConfig,
		QUICConfig: &quic.Config{
			Versions:             []quic.Version{quic.Version1},
			EnableDatagrams:      true,
			HandshakeIdleTimeout: _quicHandshakeTimeout,
			MaxIdleTimeout:       _quicMaxIdleTimeout,
			KeepAlivePeriod:      _quicKeepAlivePeriod,
			// InitialStreamReceiveWindow:     6291456,  // initial_max_stream_data_bidi_remote, initial_max_stream_data_bidi_local, initial_max_stream_data_uni
			// InitialConnectionReceiveWindow: 15728640, // initial_max_data
			// MaxIncomingStreams:             100,      // initial_max_streams_bidi
			// MaxIncomingUniStreams:          103,      // initial_max_streams_uni
		},
		AdditionalSettings:     ut.settings,
		MaxResponseHeaderBytes: _maxResponseHeaderBytes,
		Dial:                   ut.dial,
	}

	return nil
}

// createUDPPacketConn creates a UDP listener, preferring IPv4.
func (ut *uquicTransport) createUDPPacketConn() (net.PacketConn, error) {
	if conn, err := net.ListenUDP("udp4", nil); err == nil {
		return conn, nil
	}

	return net.ListenUDP("udp6", nil)
}

// dial establishes a QUIC connection, routing through SOCKS5 proxy if configured.
func (ut *uquicTransport) dial(
	ctx context.Context,
	addr string,
	tlsCfg *tls.Config,
	cfg *quic.Config,
) (*quic.Conn, error) {
	resolved, err := ut.resolve(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution: %w", err)
	}

	host, _, _ := net.SplitHostPort(addr)
	if tlsCfg.ServerName == "" && host != "" && net.ParseIP(host) == nil {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.ServerName = host
	}

	if ut.proxy != "" {
		return ut.dialSOCKS5(ctx, resolved, tlsCfg, cfg)
	}

	return ut.dialDirect(ctx, resolved, tlsCfg, cfg)
}

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
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE: %w", err)
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

	quicConn, err := quic.DialEarly(ctx, packetConn, targetUDP, tlsCfg, cfg)
	if err != nil {
		packetConn.Close()
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	success = true

	return quicConn, nil
}

// dialDirect establishes a direct QUIC connection without proxy.
func (ut *uquicTransport) dialDirect(
	ctx context.Context,
	resolved string,
	tlsCfg *tls.Config,
	cfg *quic.Config,
) (*quic.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", resolved)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP addr: %w", err)
	}

	return ut.quictr.Dial(ctx, udpAddr, tlsCfg, cfg)
}

// resolve resolves a hostname to an IP address, preferring IPv4.
func (ut *uquicTransport) resolve(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("split host/port: %w", err)
	}

	if net.ParseIP(host) != nil {
		return addr, nil
	}

	resolver := net.DefaultResolver
	if ut.dialer != nil && ut.dialer.Resolver != nil {
		resolver = ut.dialer.Resolver
	}

	ips, err := resolver.LookupIPAddr(ctx, host)
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

// RoundTrip executes an HTTP/3 request with automatic fallback to HTTP/2.
func (ut *uquicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if ut.proxy != "" && !isSOCKS5Proxy(ut.proxy) {
		if ut.fallbackTransport != nil {
			return ut.fallbackTransport.RoundTrip(req)
		}

		return nil, errors.New("non-SOCKS5 proxy requires HTTP/2 fallback")
	}

	if ut.http3tr == nil {
		if ut.fallbackTransport != nil {
			return ut.fallbackTransport.RoundTrip(req)
		}

		return nil, errors.New("no transport available")
	}

	if req.URL.Scheme == "" {
		req = cloneRequestWithScheme(req, "https")
	}

	resp, err := ut.http3tr.RoundTrip(req)
	if err != nil {
		return ut.handleError(req, err)
	}

	return resp, nil
}

// handleError attempts HTTP/2 fallback for recoverable HTTP/3 errors.
func (ut *uquicTransport) handleError(req *http.Request, err error) (*http.Response, error) {
	if req.Context().Err() != nil {
		return nil, err
	}

	if !isHTTP3UnsupportedError(err) || ut.fallbackTransport == nil {
		return nil, err
	}

	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, fmt.Errorf("HTTP/3 failed, cannot retry (GetBody is nil): %w", err)
		}

		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return nil, fmt.Errorf("failed to restore body: %w", bodyErr)
		}

		req.Body = body
	}

	return ut.fallbackTransport.RoundTrip(req)
}

// CloseIdleConnections closes idle connections while keeping the transport usable.
func (ut *uquicTransport) CloseIdleConnections() {
	if ut.http3tr != nil {
		ut.http3tr.CloseIdleConnections()
	}

	if ut.fallbackTransport != nil {
		if c, ok := ut.fallbackTransport.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}

// Close shuts down the transport and releases all resources.
func (ut *uquicTransport) Close() error {
	if ut.http3tr != nil {
		ut.http3tr.Close()
	}

	if ut.quictr != nil {
		ut.quictr.Close()
	}

	if ut.pconn != nil {
		ut.pconn.Close()
	}

	if ut.fallbackTransport != nil {
		if c, ok := ut.fallbackTransport.(interface{ Close() error }); ok {
			c.Close()
		}
	}

	return nil
}

func cloneRequestWithScheme(req *http.Request, scheme string) *http.Request {
	clone := *req
	urlClone := *req.URL
	urlClone.Scheme = scheme
	clone.URL = &urlClone

	return &clone
}

func isHTTP3UnsupportedError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return true
	}

	var handshakeErr *quic.HandshakeTimeoutError
	var idleErr *quic.IdleTimeoutError
	var versionErr *quic.VersionNegotiationError
	var resetErr *quic.StatelessResetError

	if errors.As(err, &handshakeErr) ||
		errors.As(err, &idleErr) ||
		errors.As(err, &versionErr) ||
		errors.As(err, &resetErr) {
		return true
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" || opErr.Op == "write" || opErr.Op == "read" {
			return true
		}

		var errno syscall.Errno
		if errors.As(opErr.Err, &errno) {
			switch errno {
			case syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ECONNRESET:
				return true
			}
		}
	}

	return false
}

func isSOCKS5Proxy(proxyURL string) bool {
	if proxyURL == "" {
		return false
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}

	return u.Scheme == "socks5" || u.Scheme == "socks5h"
}
