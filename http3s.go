// Package surf provides HTTP/3 support with uQUIC fingerprinting for advanced web scraping and automation.
// This file implements HTTP/3 transport with SOCKS5 proxy support and automatic fallback to HTTP/2.
package surf

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	_http "net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http3"
	"github.com/enetx/surf/pkg/quicconn"
	"github.com/quic-go/quic-go"
	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
	"github.com/wzshiming/socks5"
)

// HTTP3Settings represents HTTP/3 settings with uQUIC fingerprinting support.
// https://github.com/refraction-networking/uquic
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

	return h.builder.addCliMW(func(c *Client) {
		if !h.builder.singleton {
			h.builder.addRespMW(closeIdleConnectionsMW, 0)
		}

		quicSpec := h.getQUICSpec()
		if quicSpec.IsNone() {
			return
		}

		// Configure TLS with session cache if enabled
		tlsConfig := c.tlsConfig.Clone()
		if h.builder.session {
			tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
		}

		// Initialize TokenStore if not set to prevent panic in uQUIC
		spec := quicSpec.Some()
		if spec.InitialPacketSpec.TokenStore == nil {
			spec.InitialPacketSpec.TokenStore = uquic.NewLRUTokenStore(10, 5) // 10 origins, 5 tokens per origin
		}

		transport := &uquicTransport{
			quicSpec:          spec,
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
	}, 0)
}

type connection struct {
	packetConn net.PacketConn
	quicConn   *quic.Conn
}

// transportAdapter wraps enetx/http3.Transport to match our interface
type transportAdapter struct {
	transport *http3.Transport
}

func (s *transportAdapter) RoundTrip(req *http.Request) (*http.Response, error) {
	_req := &_http.Request{
		Method:           req.Method,
		URL:              req.URL,
		Proto:            req.Proto,
		ProtoMajor:       req.ProtoMajor,
		ProtoMinor:       req.ProtoMinor,
		Header:           _http.Header(req.Header),
		Body:             req.Body,
		ContentLength:    req.ContentLength,
		TransferEncoding: req.TransferEncoding,
		Close:            req.Close,
		Host:             req.Host,
		Form:             req.Form,
		PostForm:         req.PostForm,
		MultipartForm:    req.MultipartForm,
		Trailer:          _http.Header(req.Trailer),
		RemoteAddr:       req.RemoteAddr,
		RequestURI:       "",
		GetBody:          req.GetBody,
		Pattern:          req.Pattern,
		Cancel:           req.Cancel,
	}

	_req = _req.WithContext(req.Context())

	_resp, err := s.transport.RoundTrip(_req)
	if err != nil {
		return nil, err
	}

	return &http.Response{
		Status:        _resp.Status,
		StatusCode:    _resp.StatusCode,
		Proto:         _resp.Proto,
		ProtoMajor:    _resp.ProtoMajor,
		ProtoMinor:    _resp.ProtoMinor,
		Header:        http.Header(_resp.Header),
		Body:          _resp.Body,
		ContentLength: _resp.ContentLength,
		Close:         _resp.Close,
		Uncompressed:  _resp.Uncompressed,
		Trailer:       http.Header(_resp.Trailer),
		Request:       req,
		TLS:           _resp.TLS,
	}, nil
}

func (s *transportAdapter) CloseIdleConnections() {
	s.transport.CloseIdleConnections()
}

// applyTLSFingerprinting applies ClientHello fingerprinting from QUICSpec to TLS config
func (ut *uquicTransport) applyTLSFingerprinting(tlsConfig *tls.Config) *tls.Config {
	if ut.quicSpec.ClientHelloSpec == nil {
		return tlsConfig
	}

	// Clone the original TLS config
	fingerprinted := tlsConfig.Clone()

	// Apply HTTP/3 ALPN protocols
	fingerprinted.NextProtos = []string{"h3"}

	// Apply cipher suites from fingerprint spec
	if len(ut.quicSpec.ClientHelloSpec.CipherSuites) > 0 {
		fingerprinted.CipherSuites = ut.quicSpec.ClientHelloSpec.CipherSuites
	}

	return fingerprinted
}

// uquicTransport implements http.RoundTripper using uQUIC fingerprinting with quic-go HTTP/3.
// It provides HTTP/3 support with SOCKS5 proxy compatibility and automatic fallback to HTTP/2
// for non-SOCKS5 proxies. The transport supports both static and dynamic proxy configurations.
// It includes connection caching to avoid creating unnecessary connections.
type uquicTransport struct {
	quicSpec          uquic.QUICSpec // QUIC specification for fingerprinting
	tlsConfig         *tls.Config    // TLS configuration for QUIC connections
	dialer            *net.Dialer    // Network dialer (may contain custom DNS resolver)
	proxy             any            // Proxy configuration (static or dynamic function)
	staticProxy       string         // Cached static proxy URL for performance
	isDynamic         bool           // Flag indicating if proxy is dynamic (disables caching)
	cachedConnections *g.MapSafe[string, *connection]
	cachedTransports  *g.MapSafe[string, http.RoundTripper] // Per-address HTTP/3 transport cache
	fallbackTransport http.RoundTripper                     // HTTP/2 transport for non-SOCKS5 proxy fallback
}

// CloseIdleConnections closes all cached HTTP/3 connections and clears the cache.
// It also attempts to close idle connections on the fallback transport if available.
func (ut *uquicTransport) CloseIdleConnections() {
	for k, transport := range ut.cachedTransports.Iter() {
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
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

// defaultHTTPSPort is used when no port is specified in the URL.
const defaultHTTPSPort = "443"

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

	// Apply QUIC fingerprinting if spec is available
	var h3 http.RoundTripper

	if ut.quicSpec.ClientHelloSpec != nil {
		// Apply TLS fingerprinting using uTLS for ClientHello
		// Note: QUIC Initial Packet fingerprinting is disabled due to uquic/http3 integration issues
		fingerprinted := ut.applyTLSFingerprinting(ut.tlsConfig)
		standardTransport := &http3.Transport{TLSClientConfig: fingerprinted}
		h3 = &transportAdapter{transport: standardTransport}
	} else {
		// Fallback to standard transport without fingerprinting
		standardTransport := &http3.Transport{TLSClientConfig: ut.tlsConfig}
		h3 = &transportAdapter{transport: standardTransport}
	}

	if (ut.dialer != nil && ut.dialer.Resolver != nil) || proxy != "" {
		hostname := req.URL.Hostname()

		// Configure custom dial function
		if adapter, ok := h3.(*transportAdapter); ok {
			adapter.transport.Dial = func(ctx context.Context, quicAddr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				if tlsCfg == nil {
					tlsCfg = new(tls.Config)
				}

				// Ensure SNI for IP/UDP paths
				if tlsCfg.ServerName == "" {
					if hn := hostname; hn != "" {
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

// dialSOCKS5 establishes a QUIC connection through a SOCKS5 proxy
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

	proxyUDP, err := net.ResolveUDPAddr("udp", conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("socks5 get proxy UDP addr: %w", err)
	}

	// Create packet connection wrapper
	packetConn := quicconn.New(conn, proxyUDP, quicconn.EncapRaw)

	// Ensure QUIC config exists
	if cfg == nil {
		cfg = &quic.Config{}
	}

	// Apply TLS fingerprinting from QUICSpec if available
	finalTLSConfig := tlsConfig
	if ut.quicSpec.ClientHelloSpec != nil {
		// Apply uTLS ClientHello fingerprinting
		utlsConfig := tlsToUTLS(tlsConfig)
		utlsConfig.NextProtos = []string{"h3"}

		// Apply custom ClientHelloSpec from QUICSpec
		// Note: This is experimental and may need adjustment
		utlsConfig.CipherSuites = ut.quicSpec.ClientHelloSpec.CipherSuites

		// Convert back to standard tls.Config with applied fingerprinting
		finalTLSConfig = &tls.Config{
			ServerName:         utlsConfig.ServerName,
			InsecureSkipVerify: utlsConfig.InsecureSkipVerify,
			NextProtos:         utlsConfig.NextProtos,
			RootCAs:            utlsConfig.RootCAs,
			MinVersion:         utlsConfig.MinVersion,
			MaxVersion:         utlsConfig.MaxVersion,
			CipherSuites:       utlsConfig.CipherSuites,
		}
	}

	// Establish QUIC connection with fingerprinted TLS config
	quicConn, err := quic.Dial(ctx, packetConn, proxyUDP, finalTLSConfig, cfg)
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

// dialDNS establishes a QUIC connection using custom DNS resolver
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
		cfg = &quic.Config{}
	}

	// Apply TLS fingerprinting from QUICSpec if available
	finalTLSConfig := tlsConfig
	if ut.quicSpec.ClientHelloSpec != nil {
		// Apply uTLS ClientHello fingerprinting
		utlsConfig := tlsToUTLS(tlsConfig)
		utlsConfig.NextProtos = []string{"h3"}

		// Apply custom ClientHelloSpec from QUICSpec
		// Note: This is experimental and may need adjustment
		utlsConfig.CipherSuites = ut.quicSpec.ClientHelloSpec.CipherSuites

		// Convert back to standard tls.Config with applied fingerprinting
		finalTLSConfig = &tls.Config{
			ServerName:         utlsConfig.ServerName,
			InsecureSkipVerify: utlsConfig.InsecureSkipVerify,
			NextProtos:         utlsConfig.NextProtos,
			RootCAs:            utlsConfig.RootCAs,
			MinVersion:         utlsConfig.MinVersion,
			MaxVersion:         utlsConfig.MaxVersion,
			CipherSuites:       utlsConfig.CipherSuites,
		}
	}

	// Establish QUIC connection with fingerprinted TLS config
	quicConn, err := quic.Dial(ctx, udpConn, targetAddr, finalTLSConfig, cfg)
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
