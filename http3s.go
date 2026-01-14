package surf

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/url"
	"strconv"
	"syscall"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http3"
	"github.com/enetx/surf/pkg/quicconn"
	"github.com/quic-go/quic-go"
	"github.com/wzshiming/socks5"
)

// HTTP/3 SETTINGS constants define configurable parameters for HTTP/3 connections.
const (
	SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01
	SETTINGS_MAX_FIELD_SECTION_SIZE   = 0x06
	SETTINGS_QPACK_BLOCKED_STREAMS    = 0x07
	SETTINGS_ENABLE_CONNECT_PROTOCOL  = 0x08
	SETTINGS_H3_DATAGRAM              = 0x33
	H3_DATAGRAM                       = 0xFFD277
	SETTINGS_ENABLE_WEBTRANSPORT      = 0x2B603742
)

// HTTP3Settings represents configurable HTTP/3 SETTINGS parameters.
type HTTP3Settings struct {
	builder  *Builder
	settings g.MapOrd[uint64, uint64]
}

// QpackMaxTableCapacity sets the SETTINGS_QPACK_MAX_TABLE_CAPACITY value.
func (h *HTTP3Settings) QpackMaxTableCapacity(num uint64) *HTTP3Settings {
	h.settings.Set(SETTINGS_QPACK_MAX_TABLE_CAPACITY, num)
	return h
}

// MaxFieldSectionSize sets the SETTINGS_MAX_FIELD_SECTION_SIZE value.
func (h *HTTP3Settings) MaxFieldSectionSize(num uint64) *HTTP3Settings {
	h.settings.Set(SETTINGS_MAX_FIELD_SECTION_SIZE, num)
	return h
}

// QpackBlockedStreams sets the SETTINGS_QPACK_BLOCKED_STREAMS value.
func (h *HTTP3Settings) QpackBlockedStreams(num uint64) *HTTP3Settings {
	h.settings.Set(SETTINGS_QPACK_BLOCKED_STREAMS, num)
	return h
}

// EnableConnectProtocol sets the SETTINGS_ENABLE_CONNECT_PROTOCOL value.
func (h *HTTP3Settings) EnableConnectProtocol(num uint64) *HTTP3Settings {
	h.settings.Set(SETTINGS_ENABLE_CONNECT_PROTOCOL, num)
	return h
}

// SettingsH3Datagram sets the SETTINGS_H3_DATAGRAM value.
func (h *HTTP3Settings) SettingsH3Datagram(num uint64) *HTTP3Settings {
	h.settings.Set(SETTINGS_H3_DATAGRAM, num)
	return h
}

// H3Datagram sets a custom H3_DATAGRAM HTTP/3 SETTINGS value.
func (h *HTTP3Settings) H3Datagram(num uint64) *HTTP3Settings {
	h.settings.Set(H3_DATAGRAM, num)
	return h
}

// EnableWebtransport sets the SETTINGS_ENABLE_WEBTRANSPORT value.
func (h *HTTP3Settings) EnableWebtransport(num uint64) *HTTP3Settings {
	h.settings.Set(SETTINGS_ENABLE_WEBTRANSPORT, num)
	return h
}

// Grease adds a GREASE SETTINGS parameter with a random ID and value.
func (h *HTTP3Settings) Grease() *HTTP3Settings {
	maxn := (uint64(1<<62) - 1 - 0x21) / 0x1F
	n := uint64(rand.Uint32()) % maxn
	id := 0x1F*n + 0x21
	value := uint64(rand.Uint32())

	h.settings.Set(id, value)

	return h
}

// Set applies the accumulated HTTP/3 settings to the client's transport.
// If HTTP/3 is disabled or forced to HTTP/1/2, no changes are applied.
// Returns the Builder for method chaining.
func (h *HTTP3Settings) Set() *Builder {
	return h.builder.addCliMW(func(c *Client) error {
		if h.builder.forceHTTP1 || h.builder.forceHTTP2 || !h.builder.http3 {
			return nil
		}

		if !h.builder.singleton {
			h.builder.addRespMW(closeIdleConnectionsMW, 0)
		}

		transport := newUQUICTransport(h.settings, c, h.builder)

		c.GetClient().Transport = transport
		c.transport = transport

		return nil
	}, math.MaxInt-1)
}

// h3State encapsulates all resources needed for a single HTTP/3 connection.
// Groups the HTTP/3 transport, QUIC transport, and packet connection together
// to ensure they are managed as a single unit.
type h3State struct {
	http3tr *http3.Transport // HTTP/3 transport layer
	quictr  *quic.Transport  // QUIC transport layer
	pconn   net.PacketConn   // Underlying packet connection (UDP or SOCKS5)
}

// close closes all resources in the h3State.
// Safely handles nil values and closes in the correct order.
func (s *h3State) close() {
	if s.http3tr != nil {
		s.http3tr.Close()
	}

	if s.quictr != nil {
		s.quictr.Close()
	}

	if s.pconn != nil {
		s.pconn.Close()
	}
}

// uquicTransport implements http.RoundTripper with uQUIC fingerprinting for HTTP/3.
// Provides full QUIC Initial Packet + TLS ClientHello fingerprinting capabilities,
// SOCKS5 proxy compatibility, and automatic fallback to HTTP/2 for non-SOCKS5 proxies
// or when HTTP/3 is not supported by the server.
// Maintains a cache of HTTP/3 states per address for connection reuse.
type uquicTransport struct {
	settings          g.MapOrd[uint64, uint64]     // HTTP/3 SETTINGS parameters
	proxy             any                          // Proxy configuration (static or dynamic function)
	staticProxy       string                       // Cached static proxy URL for performance
	fallbackTransport http.RoundTripper            // HTTP/2 transport for fallback
	tlsConfig         *tls.Config                  // TLS configuration for QUIC connections
	dialer            *net.Dialer                  // Network dialer (may contain custom DNS resolver)
	cachedTransports  *g.MapSafe[string, *h3State] // Per-address HTTP/3 transport cache
	isDynamic         bool                         // Flag indicating if proxy is dynamic (disables caching)
}

// newUQUICTransport creates a new uQUIC transport with the given settings.
// Initializes the transport cache and configures proxy settings.
func newUQUICTransport(settings g.MapOrd[uint64, uint64], c *Client, builder *Builder) *uquicTransport {
	ut := &uquicTransport{
		settings:         settings,
		tlsConfig:        c.tlsConfig.Clone(),
		dialer:           c.GetDialer(),
		proxy:            builder.proxy,
		cachedTransports: g.NewMapSafe[string, *h3State](),
	}

	if !builder.forceHTTP3 {
		ut.fallbackTransport = c.GetTransport()
	}

	switch v := builder.proxy.(type) {
	case string:
		ut.staticProxy = v
	case g.String:
		ut.staticProxy = v.Std()
	default:
		ut.isDynamic = true
	}

	return ut
}

// CloseIdleConnections closes all cached HTTP/3 connections and clears the cache.
// Also closes idle connections on the fallback HTTP/2 transport if supported.
func (ut *uquicTransport) CloseIdleConnections() {
	for _, st := range ut.cachedTransports.Iter() {
		st.close()
	}

	ut.cachedTransports.Clear()

	if ut.fallbackTransport != nil {
		if c, ok := ut.fallbackTransport.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}

// RoundTrip implements the http.RoundTripper interface with HTTP/3 support.
// Handles proxy routing, creates or retrieves cached HTTP/3 states,
// and automatically falls back to HTTP/2 when appropriate.
func (ut *uquicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	proxy := ut.getProxy().UnwrapOr(ut.staticProxy)

	if proxy != "" && !isSOCKS5(proxy) {
		return ut.fallbackToHTTP2(req)
	}

	if req.URL.Scheme == "" {
		req = ut.cloneRequestWithScheme(req, "https")
	}

	addr := ut.address(req)
	st, err := ut.getOrCreateH3State(req.Context(), addr, proxy)
	if err != nil {
		return ut.handleCreateError(req, err)
	}

	resp, err := st.http3tr.RoundTrip(req)
	if err != nil {
		return ut.handleRoundTripError(req, st, addr, proxy, err)
	}

	if proxy != "" && isSOCKS5(proxy) {
		return ut.readSOCKS5Body(resp)
	}

	return resp, nil
}

// fallbackToHTTP2 falls back to the HTTP/2 transport.
// Returns an error if no fallback transport is available.
func (ut *uquicTransport) fallbackToHTTP2(req *http.Request) (*http.Response, error) {
	if ut.fallbackTransport != nil {
		return ut.fallbackTransport.RoundTrip(req)
	}

	return nil, errors.New("non-SOCKS5 proxy requires HTTP/2 fallback transport")
}

// cloneRequestWithScheme creates a shallow copy of the request with a new scheme.
// Used to ensure HTTPS scheme when not specified.
func (ut *uquicTransport) cloneRequestWithScheme(req *http.Request, scheme string) *http.Request {
	clone := *req
	urlClone := *req.URL
	urlClone.Scheme = scheme
	clone.URL = &urlClone

	return &clone
}

// address returns host:port for a request with default port if needed.
// Adds default HTTP (80) or HTTPS (443) ports when not specified.
func (ut *uquicTransport) address(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}

	defaultPort := defaultHTTPSPort
	if req.URL.Scheme == "http" {
		defaultPort = defaultHTTPPort
	}

	return net.JoinHostPort(req.URL.Host, defaultPort)
}

// getOrCreateH3State returns a cached HTTP/3 state or creates a new one.
// Caching is disabled for dynamic proxy configurations to ensure proper proxy rotation.
// The cache key is based on address and proxy combination.
func (ut *uquicTransport) getOrCreateH3State(ctx context.Context, addr, proxy string) (*h3State, error) {
	key := addr
	if proxy != "" {
		key = proxy + "|" + addr
	}

	if !ut.isDynamic {
		if st := ut.cachedTransports.Get(key); st.IsSome() {
			return st.Some(), nil
		}
	}

	st, err := ut.createH3State(ctx, addr, proxy)
	if err != nil {
		return nil, err
	}

	if !ut.isDynamic {
		ut.cachedTransports.Set(key, st)
	}

	return st, nil
}

// createH3State creates a new HTTP/3 state with all required resources.
// Creates packet connection, QUIC transport, and HTTP/3 transport in the correct order.
func (ut *uquicTransport) createH3State(ctx context.Context, addr, proxy string) (*h3State, error) {
	resolved, err := ut.resolve(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution: %w", err)
	}

	pconn, err := ut.createPacketConn(ctx, resolved, proxy)
	if err != nil {
		return nil, fmt.Errorf("create packet conn: %w", err)
	}

	quictr := &quic.Transport{Conn: pconn}

	http3tr := &http3.Transport{
		TLSClientConfig: ut.tlsConfig,
		QUICConfig: &quic.Config{
			Versions:             []quic.Version{quic.Version1},
			EnableDatagrams:      true,
			HandshakeIdleTimeout: _quicHandshakeTimeout,
			MaxIdleTimeout:       _quicMaxIdleTimeout,
			KeepAlivePeriod:      _quicKeepAlivePeriod,
		},
		AdditionalSettings:     ut.settings,
		MaxResponseHeaderBytes: _maxResponseHeaderBytes,
		Dial:                   ut.dialFunc(quictr, addr, resolved),
	}

	return &h3State{http3tr, quictr, pconn}, nil
}

// dialFunc returns a dial function for http3.Transport.
// The returned function handles SNI configuration and delegates to quic.Transport.
// Uses pre-resolved address to avoid duplicate DNS lookups.
func (ut *uquicTransport) dialFunc(
	quictr *quic.Transport,
	originalAddr string,
	resolvedAddr string,
) func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		if tlsCfg.ServerName == "" {
			if host, _, _ := net.SplitHostPort(originalAddr); host != "" && net.ParseIP(host) == nil {
				tlsCfgCopy := tlsCfg.Clone()
				tlsCfgCopy.ServerName = host
				tlsCfg = tlsCfgCopy
			}
		}

		udpAddr, err := net.ResolveUDPAddr("udp", resolvedAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve UDP addr: %w", err)
		}

		return quictr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}
}

// createPacketConn creates the appropriate PacketConn (UDP or SOCKS5).
// Routes to SOCKS5 creation if proxy is specified, otherwise creates direct UDP connection.
// Expects pre-resolved address.
func (ut *uquicTransport) createPacketConn(ctx context.Context, resolvedAddr, proxy string) (net.PacketConn, error) {
	if proxy != "" {
		return ut.createSOCKS5PacketConn(ctx, resolvedAddr, proxy)
	}

	return ut.createUDPPacketConn(resolvedAddr)
}

// createUDPPacketConn creates a direct UDP connection.
// Creates appropriate IPv4 or IPv6 UDP listener based on resolved address.
func (ut *uquicTransport) createUDPPacketConn(resolvedAddr string) (net.PacketConn, error) {
	host, _, _ := net.SplitHostPort(resolvedAddr)
	network := "udp"
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		network = "udp4"
	}

	return net.ListenUDP(network, nil)
}

// createSOCKS5PacketConn creates a SOCKS5 UDP relay connection.
// Establishes SOCKS5 UDP ASSOCIATE and wraps the connection for QUIC usage.
func (ut *uquicTransport) createSOCKS5PacketConn(
	ctx context.Context,
	resolvedAddr, proxy string,
) (net.PacketConn, error) {
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}

	dialer, err := socks5.NewDialer(proxyURL.String())
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "udp", resolvedAddr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dial: %w", err)
	}

	proxyUDP, err := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("resolve proxy UDP addr: %w", err)
	}

	return quicconn.New(conn, proxyUDP, quicconn.EncapRaw), nil
}

// handleCreateError handles errors from creating HTTP/3 state.
// Falls back to HTTP/2 transport if available.
func (ut *uquicTransport) handleCreateError(req *http.Request, err error) (*http.Response, error) {
	if ut.fallbackTransport != nil {
		return ut.fallbackTransport.RoundTrip(req)
	}

	return nil, err
}

// handleRoundTripError handles errors from HTTP/3 RoundTrip.
// Implements automatic fallback to HTTP/2 for unsupported errors.
// Cleans up failed state and restores request body for retry.
func (ut *uquicTransport) handleRoundTripError(
	req *http.Request,
	st *h3State,
	addr, proxy string,
	err error,
) (*http.Response, error) {
	if req.Context().Err() != nil {
		return nil, err
	}

	if isHTTP3UnsupportedError(err) && !ut.isForceHTTP3() && ut.fallbackTransport != nil {
		ut.cleanupFailedState(st, addr, proxy)

		if req.Body != nil && req.Body != http.NoBody {
			if req.GetBody == nil {
				return nil, fmt.Errorf("HTTP/3 failed and cannot retry: req.GetBody is nil: %w", err)
			}

			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				return nil, fmt.Errorf("failed to restore body for fallback: %w", bodyErr)
			}
			req.Body = body
		}

		return ut.fallbackTransport.RoundTrip(req)
	}

	return nil, err
}

// cleanupFailedState closes and removes failed HTTP/3 state from cache.
// Ensures all resources are properly released and the cache entry is removed.
func (ut *uquicTransport) cleanupFailedState(st *h3State, addr, proxy string) {
	st.close()

	key := addr
	if proxy != "" {
		key = proxy + "|" + addr
	}

	ut.cachedTransports.Delete(key)
}

// readSOCKS5Body reads the entire response body for SOCKS5 proxy.
// SOCKS5 UDP relay requires reading the full response before closing the connection.
// Returns a new response with the body buffered in memory.
func (ut *uquicTransport) readSOCKS5Body(resp *http.Response) (*http.Response, error) {
	if resp.Body == nil {
		return resp, nil
	}

	var (
		body    []byte
		readErr error
	)

	if resp.ContentLength > 0 {
		body = make([]byte, resp.ContentLength)
		n, err := io.ReadFull(resp.Body, body)
		if err == nil && int64(n) != resp.ContentLength {
			readErr = fmt.Errorf("read mismatch: expected %d bytes, got %d", resp.ContentLength, n)
		} else {
			readErr = err
		}
	} else {
		body, readErr = io.ReadAll(resp.Body)
	}

	resp.Body.Close()

	if readErr != nil {
		return nil, fmt.Errorf("read SOCKS5 response body: %w", readErr)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))

	return resp, nil
}

// resolve resolves a hostname to an IP address.
// Uses custom DNS resolver if configured, otherwise uses the default resolver.
// Prefers IPv4 addresses over IPv6 for better compatibility.
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

// getProxy extracts the proxy URL from the configured proxy source.
// Supports static (string) and dynamic (func() g.String) configurations.
// Returns g.Option[string] - Some(proxy_url) if proxy is available, None if no proxy is configured.
func (ut *uquicTransport) getProxy() g.Option[string] {
	var p string

	switch v := ut.proxy.(type) {
	case func() g.String:
		p = v().Std()
	case string:
		p = v
	case g.String:
		p = v.Std()
	case []string:
		if len(v) > 0 {
			p = v[rand.N(len(v))]
		}
	case g.Slice[string]:
		p = v.Random()
	case g.Slice[g.String]:
		p = v.Random().Std()
	}

	if p != "" {
		return g.Some(p)
	}

	return g.None[string]()
}

// isForceHTTP3 returns true if HTTP/3 is forced (no fallback transport available).
func (ut *uquicTransport) isForceHTTP3() bool { return ut.fallbackTransport == nil }

// isHTTP3UnsupportedError checks if an error indicates HTTP/3 is not supported by the server.
// Includes QUIC protocol errors, handshake failures, and network errors that suggest
// the server doesn't support HTTP/3 and we should fallback to HTTP/2.
// Excludes context cancellation and deadline errors which are client-driven.
func isHTTP3UnsupportedError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var (
		appErr       *quic.ApplicationError
		handshakeErr *quic.HandshakeTimeoutError
		idleErr      *quic.IdleTimeoutError
		versionErr   *quic.VersionNegotiationError
		resetErr     *quic.StatelessResetError
		opErr        *net.OpError
		errno        syscall.Errno
	)

	if errors.As(err, &appErr) {
		return true
	}

	if errors.As(err, &handshakeErr) ||
		errors.As(err, &idleErr) ||
		errors.As(err, &versionErr) ||
		errors.As(err, &resetErr) {
		return true
	}

	if errors.As(err, &opErr) {
		if opErr.Op == "dial" || opErr.Op == "write" || opErr.Op == "read" {
			return true
		}

		if errors.As(opErr.Err, &errno) {
			switch errno {
			case syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ECONNRESET:
				return true
			}
		}
	}

	return false
}

// isSOCKS5 checks if the given proxy URL is a SOCKS5 proxy.
// Only SOCKS5 proxies support UDP relay needed for QUIC/HTTP3.
// Returns true for both "socks5://" and "socks5h://" schemes.
func isSOCKS5(proxyURL string) bool {
	if proxyURL == "" {
		return false
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}

	return u.Scheme == "socks5" || u.Scheme == "socks5h"
}
