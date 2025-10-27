// Package surf provides HTTP/3 support with full uQUIC fingerprinting for advanced web scraping and automation.
// This file implements HTTP/3 transport with complete QUIC Initial Packet + TLS ClientHello fingerprinting,
// SOCKS5 proxy support, and automatic fallback to HTTP/2 for non-SOCKS5 proxies.
package surf

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/g/ref"
	"github.com/enetx/http"
	"github.com/enetx/surf/pkg/quicconn"
	uquic "github.com/enetx/uquic"
	"github.com/enetx/uquic/http3"
	utls "github.com/enetx/utls"
	"github.com/wzshiming/socks5"
)

// HTTP3Settings represents HTTP/3 settings with uQUIC fingerprinting support.
type HTTP3Settings struct {
	builder  *Builder
	quicID   *uquic.QUICID
	quicSpec *uquic.QUICSpec
}

// Chrome configures HTTP/3 settings to mimic Chrome browser.
func (h *HTTP3Settings) Chrome() *HTTP3Settings {
	h.quicID = &uquic.QUICChrome_115
	return h
}

// Firefox configures HTTP/3 settings to mimic Firefox browser.
func (h *HTTP3Settings) Firefox() *HTTP3Settings {
	h.quicID = &uquic.QUICFirefox_116
	return h
}

// SetQUICID sets a custom QUIC ID for fingerprinting.
func (h *HTTP3Settings) SetQUICID(quicID uquic.QUICID) *HTTP3Settings {
	h.quicID = &quicID
	return h
}

// SetQUICSpec sets a custom QUIC spec for advanced fingerprinting.
func (h *HTTP3Settings) SetQUICSpec(quicSpec uquic.QUICSpec) *HTTP3Settings {
	h.quicSpec = &quicSpec
	return h
}

// getQUICSpec returns the QUIC spec either from custom spec or by converting QUICID.
// Returns None if neither custom spec nor QUICID is configured or conversion fails.
func (h *HTTP3Settings) getQUICSpec() g.Option[uquic.QUICSpec] {
	if h.quicSpec != nil {
		return g.Some(*h.quicSpec)
	}

	if h.quicID != nil {
		if spec, err := uquic.QUICID2Spec(*h.quicID); err == nil {
			return g.Some(spec)
		}
	}

	return g.None[uquic.QUICSpec]()
}

// Set applies the accumulated HTTP/3 settings.
// It configures the uQUIC transport for the surf client.
func (h *HTTP3Settings) Set() *Builder {
	if h.builder.forseHTTP1 {
		return h.builder
	}

	return h.builder.addCliMW(func(c *Client) error {
		if !h.builder.singleton {
			h.builder.addRespMW(closeIdleConnectionsMW, 0)
		}

		quicSpec := h.getQUICSpec()
		if quicSpec.IsNone() {
			return nil
		}

		tlsConfig := c.tlsConfig.Clone()

		transport := &uquicTransport{
			quicSpec:          ref.Of(quicSpec.Some()),
			tlsConfig:         tlsConfig,
			dialer:            c.GetDialer(),
			proxy:             h.builder.proxy,
			fallbackTransport: c.GetTransport(),
			cachedConnections: g.NewMapSafe[string, *connection](),
			cachedTransports:  g.NewMapSafe[string, http.RoundTripper](),
		}

		switch v := h.builder.proxy.(type) {
		case string:
			transport.staticProxy = v
			transport.isDynamic = false
		case g.String:
			transport.staticProxy = v.Std()
			transport.isDynamic = false
		default:
			transport.isDynamic = true
		}

		c.GetClient().Transport = transport
		c.transport = transport

		return nil
	}, math.MaxInt)
}

type connection struct {
	packetConn net.PacketConn
	quicConn   uquic.Connection
}

// uquicTransport implements http.RoundTripper using uQUIC fingerprinting for HTTP/3.
// It provides full QUIC Initial Packet + TLS ClientHello fingerprinting capabilities,
// SOCKS5 proxy compatibility, and automatic fallback to HTTP/2 for non-SOCKS5 proxies.
// The transport supports both static and dynamic proxy configurations with connection caching.
type uquicTransport struct {
	quicSpec          *uquic.QUICSpec // QUIC specification for fingerprinting
	tlsConfig         *tls.Config     // TLS configuration for QUIC connections
	dialer            *net.Dialer     // Network dialer (may contain custom DNS resolver)
	proxy             any             // Proxy configuration (static or dynamic function)
	staticProxy       string          // Cached static proxy URL for performance
	isDynamic         bool            // Flag indicating if proxy is dynamic (disables caching)
	cachedConnections *g.MapSafe[string, *connection]
	cachedTransports  *g.MapSafe[string, http.RoundTripper] // Per-address HTTP/3 transport cache
	fallbackTransport http.RoundTripper                     // HTTP/2 transport for non-SOCKS5 proxy fallback
}

// CloseIdleConnections closes all cached HTTP/3 connections and clears the cache.
// It also attempts to close idle connections on the fallback transport if available.
func (ut *uquicTransport) CloseIdleConnections() {
	for k, transport := range ut.cachedTransports.Iter() {
		// Check if transport implements CloseIdleConnections
		switch t := transport.(type) {
		case *http3.RoundTripper:
			t.CloseIdleConnections()
		case *http3.URoundTripper:
			t.CloseIdleConnections()
		}

		ut.cachedTransports.Delete(k)
	}

	for id, c := range ut.cachedConnections.Iter() {
		if c.quicConn != nil {
			_ = c.quicConn.CloseWithError(0, "idle close")
		}

		if c.packetConn != nil {
			_ = c.packetConn.Close()
		}

		ut.cachedConnections.Delete(id)
	}

	if ut.fallbackTransport != nil {
		if closer, ok := ut.fallbackTransport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

// address builds host:port address from HTTP request, defaulting to port 443 for HTTPS if port is missing.
func (ut *uquicTransport) address(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}

	return net.JoinHostPort(req.URL.Host, defaultHTTPSPort)
}

// createH3 returns per-address cached http3.Transport with proper Dial & SNI configuration.
// Caching is disabled for dynamic proxy configurations to ensure proper proxy rotation.
func (ut *uquicTransport) createH3(req *http.Request, addr, proxy string) http.RoundTripper {
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
	base := &http3.RoundTripper{
		TLSClientConfig: tlsToUTLS(ut.tlsConfig),
		QuicConfig:      &uquic.Config{},
	}

	var h3 http.RoundTripper
	if ut.quicSpec != nil {
		h3 = http3.GetURoundTripper(base, ut.quicSpec, nil)
	} else {
		h3 = base
	}

	if (ut.dialer != nil && ut.dialer.Resolver != nil) || proxy != "" {
		hostname := req.URL.Hostname()

		// Create common dial function
		dialFunc := func(ctx context.Context, quicAddr string, tlsCfg *utls.Config, cfg *uquic.Config) (uquic.EarlyConnection, error) {
			if tlsCfg == nil {
				tlsCfg = &utls.Config{}
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

		// Configure custom dial function for uquic/http3
		switch rt := h3.(type) {
		case *http3.URoundTripper:
			if rt.RoundTripper != nil {
				rt.RoundTripper.Dial = dialFunc
			}
			rt.Dial = dialFunc
		case *http3.RoundTripper:
			rt.Dial = dialFunc
		}
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

	return h3.RoundTrip(req)
}

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

// tlsToUTLS converts standard tls.Config to utls.Config with minimal compatibility
func tlsToUTLS(tlsConf *tls.Config) *utls.Config {
	if tlsConf == nil {
		return &utls.Config{}
	}

	return &utls.Config{
		ServerName:         tlsConf.ServerName,
		InsecureSkipVerify: tlsConf.InsecureSkipVerify,
		NextProtos:         tlsConf.NextProtos,
		RootCAs:            tlsConf.RootCAs,
		MinVersion:         tlsConf.MinVersion,
		MaxVersion:         tlsConf.MaxVersion,
		CipherSuites:       tlsConf.CipherSuites,
	}
}

// dialSOCKS5 establishes a QUIC connection through a SOCKS5 proxy (for uquic)
func (ut *uquicTransport) dialSOCKS5(
	ctx context.Context,
	address string,
	tlsConfig *utls.Config,
	cfg *uquic.Config,
	proxy string,
) (uquic.EarlyConnection, error) {
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

	proxyUDP, err := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("socks5 get proxy UDP addr: %w", err)
	}

	// Create packet connection wrapper
	packetConn := quicconn.New(conn, proxyUDP, quicconn.EncapRaw)

	// Ensure QUIC config exists
	if cfg == nil {
		cfg = &uquic.Config{}
	}

	// Establish QUIC connection with uquic
	quicConn, err := uquic.DialEarly(ctx, packetConn, proxyUDP, tlsConfig, cfg)
	if err != nil {
		_ = packetConn.Close()
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	success = true

	// Cache connection for reuse
	if ut.cachedConnections != nil {
		key := quicconn.ConnKey(packetConn)
		ut.cachedConnections.Set(key, &connection{
			packetConn: packetConn,
			quicConn:   quicConn,
		})
	}

	return quicConn, nil
}

// dialDNS establishes a QUIC connection using custom DNS resolver (for uquic)
func (ut *uquicTransport) dialDNS(
	ctx context.Context,
	address string,
	tlsConfig *utls.Config,
	cfg *uquic.Config,
) (uquic.EarlyConnection, error) {
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

	// Create target address
	targetAddr := &net.UDPAddr{
		IP:   addr.IP,
		Port: addr.Port,
	}

	// Set deadline for dial operation only
	if deadline, ok := ctx.Deadline(); ok {
		if err := udpConn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set dial deadline: %w", err)
		}

		defer func() {
			if success {
				_ = udpConn.SetDeadline(time.Time{})
			}
		}()
	}

	// Ensure QUIC config exists
	if cfg == nil {
		cfg = &uquic.Config{}
	}

	// Establish QUIC connection with uquic
	quicConn, err := uquic.DialEarly(ctx, udpConn, targetAddr, tlsConfig, cfg)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	success = true

	// Cache connection for reuse
	if ut.cachedConnections != nil {
		key := quicconn.ConnKey(udpConn)
		ut.cachedConnections.Set(key, &connection{
			packetConn: udpConn,
			quicConn:   quicConn,
		})
	}

	return quicConn, nil
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
