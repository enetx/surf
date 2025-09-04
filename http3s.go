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

		transport := &uquicTransport{
			quicSpec:          quicSpec.Some(),
			tlsConfig:         tlsConfig,
			dialer:            c.GetDialer(),
			proxy:             h.builder.proxy,
			fallbackTransport: c.GetTransport(),
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

// uquicTransport implements http.RoundTripper using uQUIC fingerprinting with quic-go HTTP/3.
// It provides HTTP/3 support with SOCKS5 proxy compatibility and automatic fallback to HTTP/2
// for non-SOCKS5 proxies. The transport supports both static and dynamic proxy configurations.
type uquicTransport struct {
	quicSpec          uquic.QUICSpec    // QUIC specification for fingerprinting
	tlsConfig         *tls.Config       // TLS configuration for QUIC connections
	dialer            *net.Dialer       // Network dialer (may contain custom DNS resolver)
	proxy             any               // Proxy configuration (static or dynamic function)
	staticProxy       string            // Cached static proxy URL for performance
	isDynamic         bool              // Flag indicating if proxy is dynamic (disables caching)
	fallbackTransport http.RoundTripper // HTTP/2 transport for non-SOCKS5 proxy fallback
}

// CloseIdleConnections attempts to close idle connections on the fallback transport if available.
func (ut *uquicTransport) CloseIdleConnections() {
	if ut.fallbackTransport != nil {
		if closer, ok := ut.fallbackTransport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

// createH3 returns per-address cached http3.Transport with proper Dial & SNI configuration.
// Caching is disabled for dynamic proxy configurations to ensure proper proxy rotation.
func (ut *uquicTransport) createH3(req *http.Request, proxy string) *http3.Transport {
	h3 := &http3.Transport{TLSClientConfig: ut.tlsConfig}

	if (ut.dialer != nil && ut.dialer.Resolver != nil) || proxy != "" {
		hostname := req.URL.Hostname()

		// Configure custom dial function
		h3.Dial = func(ctx context.Context, quicAddr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
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

	return h3
}

// resolve always resolves host:port to ip:port.
// Uses custom resolver when provided, otherwise the system resolver.
func (ut *uquicTransport) resolve(ctx context.Context, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}

	r := net.DefaultResolver
	if ut.dialer != nil && ut.dialer.Resolver != nil {
		r = ut.dialer.Resolver
	}

	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}

	if len(ips) == 0 {
		return "", &net.DNSError{Err: "no such host", Name: host}
	}

	ip := ips[rand.Intn(len(ips))].IP

	return net.JoinHostPort(ip.String(), port), nil
}

const (
	normalConnectionTimeout = 2 * time.Minute
	proxyConnectionTimeout  = 3 * time.Minute
)

// connectionCleanup spawns a goroutine that closes packetConn when conn terminates
// or after a timeout (2min for direct, 3min for proxy).
func connectionCleanup(conn *quic.Conn, packetConn net.PacketConn, isProxy bool) {
	timeout := normalConnectionTimeout
	reason := "connection timeout"

	if isProxy {
		timeout = proxyConnectionTimeout
		reason = "proxy timeout"
	}

	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-conn.Context().Done():
			_ = packetConn.Close()
		case <-timer.C:
			_ = packetConn.Close()
			_ = conn.CloseWithError(0, reason)
		}
	}()
}

// dialSOCKS5 establishes a QUIC connection through a SOCKS5 proxy.
// Uses custom DNS resolver if available before connecting through proxy.
func (ut *uquicTransport) dialSOCKS5(
	ctx context.Context,
	address string,
	tlsConfig *tls.Config,
	cfg *quic.Config,
	proxy string,
) (*quic.Conn, error) {
	resolvedAddress, err := ut.resolve(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("socks5 resolve target: %w", err)
	}

	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("socks5 parse proxy url: %w", err)
	}

	dialer, err := socks5.NewDialer(proxyURL.String())
	if err != nil {
		return nil, fmt.Errorf("socks5 new dialer: %w", err)
	}

	conn, err := dialer.DialContext(ctx, "udp", resolvedAddress)
	if err != nil {
		return nil, fmt.Errorf("socks5 udp associate: %w", err)
	}

	host, portStr, err := net.SplitHostPort(resolvedAddress)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("split host/port: %w", err)
	}

	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	var remoteAddr *net.UDPAddr
	if ip := net.ParseIP(host); ip != nil {
		remoteAddr = &net.UDPAddr{IP: ip, Port: p}
	} else {
		remoteAddr = &net.UDPAddr{Port: p}
	}

	// wzshiming/socks5 relays datagrams as raw bytes (no RFC1928 header):
	packetConn := quicconn.New(conn, remoteAddr, quicconn.EncapRaw)

	// If your relay expects RFC1928 headers on the wire, switch to:
	// packetConn := quicconn.New(conn, remoteAddr, quicconn.EncapSocks5)

	c, err := quic.Dial(ctx, packetConn, remoteAddr, tlsConfig, cfg)
	if err != nil {
		_ = packetConn.Close()
		return nil, fmt.Errorf("quic dial via socks5: %w", err)
	}

	connectionCleanup(c, packetConn, true)

	return c, nil
}

// dialDNS establishes a QUIC connection using custom DNS resolver.
func (ut *uquicTransport) dialDNS(
	ctx context.Context,
	address string,
	tlsConfig *tls.Config,
	cfg *quic.Config,
) (*quic.Conn, error) {
	resolvedAddress, err := ut.resolve(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("dns resolve: %w", err)
	}

	host, port, err := net.SplitHostPort(resolvedAddress)
	if err != nil {
		return nil, fmt.Errorf("split host/port: %w", err)
	}

	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return nil, fmt.Errorf("invalid port %q: %w", port, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip after resolve: %q", host)
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = udpConn.SetDeadline(dl)
	}

	targetAddr := &net.UDPAddr{IP: ip, Port: p}

	conn, err := quic.Dial(ctx, udpConn, targetAddr, tlsConfig, cfg)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	connectionCleanup(conn, udpConn, false)

	return conn, nil
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
		Cancel:           req.Cancel, // deprecated but kept for compatibility
	}

	_req = _req.WithContext(req.Context())

	h3 := ut.createH3(req, proxy)
	defer h3.CloseIdleConnections()

	_resp, err := h3.RoundTrip(_req)
	if err != nil {
		return nil, err
	}

	return &http.Response{
		Status:           _resp.Status,
		StatusCode:       _resp.StatusCode,
		Proto:            _resp.Proto,
		ProtoMajor:       _resp.ProtoMajor,
		ProtoMinor:       _resp.ProtoMinor,
		Header:           http.Header(_resp.Header),
		Body:             _resp.Body,
		ContentLength:    _resp.ContentLength,
		Close:            _resp.Close,
		Uncompressed:     _resp.Uncompressed,
		Trailer:          http.Header(_resp.Trailer),
		Request:          req,
		TLS:              _resp.TLS,
		TransferEncoding: _resp.TransferEncoding,
	}, nil
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

// isSOCKS5 checks if the given proxy URL is a SOCKS5 proxy supporting UDP.
// Only SOCKS5 proxies are compatible with QUIC/HTTP3 due to UDP requirements.
func isSOCKS5(proxyURL string) bool {
	if proxyURL == "" {
		return false
	}

	u, err := url.Parse(proxyURL)

	return err == nil && u.Scheme == "socks5"
}
