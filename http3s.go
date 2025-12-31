// Package surf provides HTTP/3 support with full uQUIC fingerprinting for advanced web scraping and automation.
// This file implements HTTP/3 transport with complete QUIC Initial Packet + TLS ClientHello fingerprinting,
// SOCKS5 proxy support, and automatic fallback to HTTP/2 for non-SOCKS5 proxies or when HTTP/3 is not supported by the server.
package surf

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http3"
	"github.com/enetx/surf/pkg/quicconn"
	"github.com/quic-go/quic-go"
	"github.com/wzshiming/socks5"
)

func http3MW(client *Client, b *Builder) error {
	if b.forceHTTP1 || b.forceHTTP2 {
		return nil
	}

	if !b.singleton {
		b.addRespMW(closeIdleConnectionsMW, 0)
	}

	tlsConfig := client.tlsConfig.Clone()

	transport := &uquicTransport{
		tlsConfig:        tlsConfig,
		dialer:           client.GetDialer(),
		proxy:            b.proxy,
		cachedTransports: g.NewMapSafe[string, *http3.Transport](),
	}

	if !b.forceHTTP3 {
		transport.fallbackTransport = client.GetTransport()
	}

	switch v := b.proxy.(type) {
	case string:
		transport.staticProxy = v
		transport.isDynamic = false
	case g.String:
		transport.staticProxy = v.Std()
		transport.isDynamic = false
	default:
		transport.isDynamic = true
	}

	client.GetClient().Transport = transport
	client.transport = transport

	return nil
}

// uquicTransport implements http.RoundTripper using uQUIC fingerprinting for HTTP/3.
// It provides full QUIC Initial Packet + TLS ClientHello fingerprinting capabilities,
// SOCKS5 proxy compatibility, and automatic fallback to HTTP/2 for non-SOCKS5 proxies
// or when HTTP/3 is not supported by the server.
// The transport supports both static and dynamic proxy configurations with connection caching.
type uquicTransport struct {
	tlsConfig         *tls.Config                          // TLS configuration for QUIC connections
	dialer            *net.Dialer                          // Network dialer (may contain custom DNS resolver)
	proxy             any                                  // Proxy configuration (static or dynamic function)
	staticProxy       string                               // Cached static proxy URL for performance
	isDynamic         bool                                 // Flag indicating if proxy is dynamic (disables caching)
	cachedTransports  *g.MapSafe[string, *http3.Transport] // Per-address HTTP/3 transport cache
	fallbackTransport http.RoundTripper                    // HTTP/2 transport for non-SOCKS5 proxy fallback
}

// CloseIdleConnections closes all cached HTTP/3 connections and clears the cache.
// It also attempts to close idle connections on the fallback transport if available.
func (ut *uquicTransport) CloseIdleConnections() {
	for k, h3 := range ut.cachedTransports.Iter() {
		h3.CloseIdleConnections()
		ut.cachedTransports.Delete(k)
	}

	if ut.fallbackTransport != nil {
		if closer, ok := ut.fallbackTransport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func (ut *uquicTransport) address(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}

	var defaultPort string

	switch g.String(req.URL.Scheme).Lower() {
	case "http":
		defaultPort = defaultHTTPPort
	case "https":
		defaultPort = defaultHTTPSPort
	default:
		defaultPort = defaultHTTPSPort
	}

	return net.JoinHostPort(req.URL.Host, defaultPort)
}

// createH3 returns per-address cached http3.Transport with proper Dial & SNI configuration.
// Caching is disabled for dynamic proxy configurations to ensure proper proxy rotation.
func (ut *uquicTransport) createH3(req *http.Request, addr, proxy string) *http3.Transport {
	key := addr
	if proxy != "" {
		key = proxy + "|" + addr
	}

	// Skip cache for dynamic proxy providers to ensure proxy rotation works correctly
	if !ut.isDynamic {
		if tr := ut.cachedTransports.Get(key); tr.IsSome() {
			return tr.Some()
		}
	}

	// Create uquic/http3 RoundTripper (with or without full QUIC fingerprinting)
	h3 := &http3.Transport{
		TLSClientConfig: ut.tlsConfig,
		QUICConfig:      new(quic.Config),
	}

	if (ut.dialer != nil && ut.dialer.Resolver != nil) || proxy != "" {
		hostname := req.URL.Hostname()

		// Create common dial function
		dialFunc := func(ctx context.Context, quicAddr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			if tlsCfg == nil {
				tlsCfg = new(tls.Config)
			}

			if tlsCfg.ServerName == "" {
				if hn := hostname; hn != "" && net.ParseIP(hn) == nil {
					clone := tlsCfg.Clone()
					clone.ServerName = hn
					tlsCfg = clone
				}
			}

			if proxy != "" {
				return ut.dialSOCKS5(ctx, quicAddr, tlsCfg, cfg, proxy)
			}

			return ut.dialDNS(ctx, quicAddr, tlsCfg, cfg)
		}

		h3.Dial = dialFunc
	}

	// Only cache transport if not using dynamic proxy provider
	if !ut.isDynamic {
		ut.cachedTransports.Set(key, h3)
	}

	return h3
}

// resolve always resolves host:port to ip:port.
// Uses custom resolver when provided, otherwise the system resolver.
func (ut *uquicTransport) resolve(ctx context.Context, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid address format: %w", err)
	}

	// Skip resolution for IP addresses
	if ip := net.ParseIP(host); ip != nil {
		return address, nil
	}

	r := net.DefaultResolver
	if ut.dialer != nil && ut.dialer.Resolver != nil {
		r = ut.dialer.Resolver
	}

	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("lookup failed for %q: %w", host, err)
	}

	if len(ips) == 0 {
		return "", &net.DNSError{Err: "no IP addresses found", Name: host}
	}

	// Prefer IPv4 addresses for better compatibility
	for _, ipa := range ips {
		if v4 := ipa.IP.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), port), nil
		}
	}

	// Fallback to first IPv6 address
	return net.JoinHostPort(ips[0].IP.String(), port), nil
}

const (
	minPort = 1
	maxPort = 65535
)

// parsedAddr represents validated network address components
type parsedAddr struct {
	IP   net.IP
	Port int
}

// parseResolvedAddress validates and parses a resolved address
func parseResolvedAddress(resolved string) (*parsedAddr, error) {
	host, portStr, err := net.SplitHostPort(resolved)
	if err != nil {
		return nil, fmt.Errorf("split host/port: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("parse port %q: %w", portStr, err)
	}

	if port < minPort || port > maxPort {
		return nil, fmt.Errorf("port %d out of valid range [%d-%d]", port, minPort, maxPort)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %q", host)
	}

	return &parsedAddr{
		IP:   ip,
		Port: port,
	}, nil
}

// createUDPListener creates a UDP listener with fallback support
func createUDPListener(preferredNetwork string) (*net.UDPConn, error) {
	// Try preferred network first
	conn, err := net.ListenUDP(preferredNetwork, nil)
	if err == nil {
		return conn, nil
	}

	// If specific version failed, try generic UDP
	if preferredNetwork != "udp" {
		conn, err = net.ListenUDP("udp", nil)
		if err == nil {
			return conn, nil
		}
	}

	return nil, fmt.Errorf("failed to create UDP listener on %s: %w", preferredNetwork, err)
}

// RoundTrip implements the http.RoundTripper interface with HTTP/3 support and automatic proxy fallback.
// For non-SOCKS5 proxies, it automatically falls back to the HTTP/2 transport.
// If HTTP/3 is not supported by the server, it automatically falls back to HTTP/2.
// Dynamic proxy configurations are evaluated on each request for proper rotation.
func (ut *uquicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var proxy string

	if ut.isDynamic {
		if p := ut.getProxy(); p.IsSome() {
			proxy = p.Some()
		}
	} else {
		proxy = ut.staticProxy
	}

	if proxy != "" && !isSOCKS5(proxy) && ut.fallbackTransport != nil {
		return ut.fallbackTransport.RoundTrip(req)
	}

	if req.URL.Scheme == "" {
		clone := *req.URL
		clone.Scheme = "https"
		req.URL = &clone
	}

	addr := ut.address(req)
	h3 := ut.createH3(req, addr, proxy)

	resp, err := h3.RoundTrip(req)
	if err != nil {
		// Check if context was cancelled - don't fallback in that case
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, err
		}

		// Check if error indicates HTTP/3 is not supported and fallback is available
		if !ut.isForceHTTP3() && ut.fallbackTransport != nil && isHTTP3UnsupportedError(err) {
			if req.Body != nil && req.Body != http.NoBody {
				if req.GetBody == nil {
					return nil, fmt.Errorf("surf: HTTP/3 failed and cannot retry because req.GetBody is nil: %w", err)
				}

				body, err := req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("surf: failed to restore body for fallback: %w", err)
				}

				req.Body = body
			}

			key := addr
			if proxy != "" {
				key = proxy + "|" + addr
			}

			h3.CloseIdleConnections()
			ut.cachedTransports.Delete(key)

			// Fallback to HTTP/2
			return ut.fallbackTransport.RoundTrip(req)
		}

		return nil, err
	}

	if resp.Body != nil && proxy != "" && isSOCKS5(proxy) {
		var (
			body []byte
			err  error
		)

		if resp.ContentLength > 0 {
			body = make([]byte, resp.ContentLength)
			var n int
			n, err = io.ReadFull(resp.Body, body)
			if err == nil && int64(n) != resp.ContentLength {
				err = fmt.Errorf("read mismatch for SOCKS5 proxy: expected %d bytes, got %d", resp.ContentLength, n)
			}
		} else {
			var buf bytes.Buffer
			_, err = io.Copy(&buf, resp.Body)
			body = buf.Bytes()
		}

		resp.Body.Close()

		if err != nil {
			return nil, fmt.Errorf("failed to read response body via SOCKS5: %w", err)
		}

		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}

	return resp, nil
}

func (ut *uquicTransport) isForceHTTP3() bool { return ut.fallbackTransport == nil }

// getProxy extracts proxy URL from configured proxy source.
// Supports static (string, []string) and dynamic (func() g.String) configurations.
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
			p = v[rand.Intn(len(v))]
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

// dialSOCKS5 establishes a QUIC connection through a SOCKS5 proxy (for uquic)
func (ut *uquicTransport) dialSOCKS5(
	ctx context.Context,
	address string,
	tlsConfig *tls.Config,
	cfg *quic.Config,
	proxy string,
) (*quic.Conn, error) {
	// Validate proxy URL
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}

	// Create SOCKS5 dialer
	dialer, err := socks5.NewDialer(proxyURL.String())
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	// Resolve target address
	resolved, err := ut.resolve(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	// Establish SOCKS5 UDP associate
	conn, err := dialer.DialContext(ctx, "udp", resolved)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 UDP associate: %w", err)
	}

	// Ensure cleanup on error
	success := false

	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set socks5 dial deadline: %w", err)
		}

		defer func() {
			if success {
				_ = conn.SetDeadline(time.Time{})
			}
		}()
	}

	proxyUDP, err := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("socks5 get proxy UDP addr: %w", err)
	}

	// Create packet connection wrapper
	packetConn := quicconn.New(conn, proxyUDP, quicconn.EncapRaw)

	// Ensure QUIC config exists
	if cfg == nil {
		cfg = new(quic.Config)
	}

	// Establish QUIC connection with uquic
	quicConn, err := quic.DialEarly(ctx, packetConn, proxyUDP, tlsConfig, cfg)
	if err != nil {
		_ = packetConn.Close()
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	success = true

	return quicConn, nil
}

// dialDNS establishes a QUIC connection using custom DNS resolver (for uquic)
func (ut *uquicTransport) dialDNS(
	ctx context.Context,
	address string,
	tlsConfig *tls.Config,
	cfg *quic.Config,
) (*quic.Conn, error) {
	// Resolve address using custom DNS
	resolved, err := ut.resolve(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	// Parse and validate resolved address
	addr, err := parseResolvedAddress(resolved)
	if err != nil {
		return nil, err
	}

	// Determine optimal network type
	network := "udp"
	if addr.IP.To4() != nil {
		network = "udp4"
	} else if addr.IP.To16() != nil {
		network = "udp6"
	}

	// Create UDP listener with fallback
	udpConn, err := createUDPListener(network)
	if err != nil {
		return nil, fmt.Errorf("create UDP listener: %w", err)
	}

	// Ensure cleanup on error
	success := false

	defer func() {
		if !success {
			_ = udpConn.Close()
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := udpConn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set udp dial deadline: %w", err)
		}

		defer func() {
			if success {
				_ = udpConn.SetDeadline(time.Time{})
			}
		}()
	}

	// Create target address
	targetAddr := &net.UDPAddr{IP: addr.IP, Port: addr.Port}

	// Ensure QUIC config exists
	if cfg == nil {
		cfg = new(quic.Config)
	}

	// Establish QUIC connection with uquic
	quicConn, err := quic.DialEarly(ctx, udpConn, targetAddr, tlsConfig, cfg)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	success = true

	return quicConn, nil
}

// isHTTP3UnsupportedError checks if an error indicates that HTTP/3 is not supported by the server.
// This includes connection errors, QUIC handshake failures, and network errors that suggest
// the server doesn't support HTTP/3 and we should fallback to HTTP/2.
func isHTTP3UnsupportedError(err error) bool {
	if err == nil {
		return false
	}

	// client-driven cancel / deadline is not unsupported H3
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// QUIC protocol-level
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return true
	}

	if errors.Is(err, &quic.HandshakeTimeoutError{}) ||
		errors.Is(err, &quic.IdleTimeoutError{}) ||
		errors.Is(err, &quic.VersionNegotiationError{}) ||
		errors.Is(err, &quic.StatelessResetError{}) {
		return true
	}

	// network / syscall errors
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

	fallbacks := g.Slice[g.String]{
		"no application protocol",
		"alpn",
		"version negotiation",
		"unsupported quic version",
		"handshake failure",
		"no recent network activity",
	}

	return g.String(err.Error()).Lower().ContainsAny(fallbacks...)
}

// isSOCKS5 checks if the given proxy URL is a SOCKS5 proxy supporting UDP.
// Only SOCKS5 proxies are compatible with QUIC/HTTP3 due to UDP requirements.
func isSOCKS5(proxyURL string) bool {
	if proxyURL == "" {
		return false
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}

	scheme := u.Scheme

	return scheme == "socks5" || scheme == "socks5h"
}
