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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/header"
	utls "github.com/refraction-networking/utls"
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

// HTTP3Settings configures HTTP/3 SETTINGS, response limits and request options.
// Use Builder.QUICSettings for the underlying QUIC transport and handshake.
type HTTP3Settings struct {
	discovery                 bool
	expireFailedAlternatives  bool
	httpsRecordsLookup        HTTPSRecordsLookup
	alternativeServiceBackoff AlternativeServiceBackoff
	addressFallbackDelay      time.Duration
	connectionRacing          bool
	connectionRacingPolicy    ConnectionRacingPolicy
	tcpFallbackDelay          *time.Duration
	altUsed                   bool
	earlyData                 bool
	clientHandshake           *quic.ClientHandshake
	clientHelloFactory        func() (utls.ClientHelloSpec, error)
	builder                   *Builder
	settings                  g.MapOrd[uint64, uint64]
	quicConfig                *quic.Config
	qpackConfig               *http3.QPACKConfig
	wireConfig                *http3.WireConfig
	connectionIDLength        *int
	connectionIDGenerator     quic.ConnectionIDGenerator
	streamPriority            *http3.StreamPriority
	maxResponseHeaderBytes    int
	datagrams                 *bool
	registered                bool
}

// QpackMaxTableCapacity sets the advertised and enforced receive-side QPACK
// dynamic table capacity. Zero selects the static-only decoder.
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

// EnableWebtransport advertises a WebTransport setting. It does not implement
// a WebTransport application protocol.
func (h *HTTP3Settings) EnableWebtransport(num uint64) *HTTP3Settings {
	h.settings.Insert(SETTINGS_ENABLE_WEBTRANSPORT, num)
	return h
}

// Grease generates a fresh reserved SETTINGS identifier/value per connection.
// Call GreaseFactory(nil) to disable generated SETTINGS GREASE.
func (h *HTTP3Settings) Grease() *HTTP3Settings {
	return h.GreaseFactory(func() (uint64, uint64, error) {
		return 0x1f*uint64(rand.Uint32()) + 0x21, uint64(rand.Uint32()), nil
	})
}

// GreaseFactory generates one reserved SETTINGS pair for each new HTTP/3
// connection. It must be concurrency safe, return promptly and not reenter the
// transport. Nil disables it. Errors are returned before control-stream writes.
func (h *HTTP3Settings) GreaseFactory(factory func() (uint64, uint64, error)) *HTTP3Settings {
	h.wire().SettingsGrease = factory
	return h
}

// Set applies the configured HTTP/3 settings to the client's transport.
func (h *HTTP3Settings) Set() *Builder {
	if h.registered {
		return h.builder
	}

	h.registered = true

	return h.builder.addCliMW(func(c *Client) error {
		if h.builder.forceHTTP1 || h.builder.forceHTTP2 || (!h.builder.forceHTTP3 && !h.discovery) {
			return nil
		}

		// An application-owned transport or TLS dialer keeps ownership of its
		// connection policy. Automatic discovery also needs reusable TCP pools.
		if h.discovery && !h.builder.forceHTTP3 {
			base := c.GetTransport()
			if _, ok := base.(connectionPreconnector); !ok {
				return nil
			}

			if tcp, ok := base.(*http.Transport); ok &&
				(tcp.DisableKeepAlives || tcp.MaxIdleConnsPerHost < 0 || tcp.DialTLSContext != nil) {
				return nil
			}
		}

		transport, err := newUQUICTransport(h, c, h.builder)
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
	sharedMu               sync.Mutex
	sharedClosed           bool
	lazySharedQUIC         bool
	discovery              *alternativeDiscovery
	addressFallbackDelay   time.Duration
	racer                  *connectionRace
	protocolHeaders        requestHeadersPolicy
	qpackConfig            *http3.QPACKConfig
	wireConfig             *http3.WireConfig
	altUsed                bool
	earlyData              bool
	configureHandshake     func(*quic.Config) error
	receivePacketSize      int
	http3tr                *http3.Transport
	quictr                 *quic.Transport
	pconn                  net.PacketConn
	fallbackTransport      http.RoundTripper
	requestProxy           func(*http.Request) (*url.URL, error)
	tlsConfig              *tls.Config
	dialer                 *net.Dialer
	settings               g.MapOrd[uint64, uint64]
	proxy                  string
	quicConfig             *quic.Config
	connectionIDLength     int
	connectionIDGenerator  quic.ConnectionIDGenerator
	streamPriority         *http3.StreamPriority
	dedicatedConn          bool
	maxResponseHeaderBytes int
	datagrams              *bool
	disableCompression     bool
}

// newUQUICTransport creates a new HTTP/3 transport with the given settings.
func newUQUICTransport(settings *HTTP3Settings, c *Client, builder *Builder) (*uquicTransport, error) {
	if err := settings.validateQUICConfig(); err != nil {
		return nil, err
	}

	ut := &uquicTransport{
		protocolHeaders:        builder.protocolHeaders,
		lazySharedQUIC:         settings.discovery && !builder.forceHTTP3,
		addressFallbackDelay:   settings.addressFallbackDelay,
		qpackConfig:            settings.qpackConfig.Clone(),
		wireConfig:             settings.wireConfig.Clone(),
		altUsed:                settings.altUsed,
		earlyData:              settings.earlyData,
		tlsConfig:              c.tlsConfig.Clone(),
		dialer:                 c.GetDialer(),
		settings:               settings.settings.Clone(),
		proxy:                  builder.proxy.Std(),
		quicConfig:             cloneQUICConfig(settings.quicConfig),
		connectionIDGenerator:  settings.connectionIDGenerator,
		maxResponseHeaderBytes: settings.maxResponseHeaderBytes,
		disableCompression:     builder.disableCompression,
	}

	if settings.connectionIDLength != nil {
		ut.connectionIDLength = *settings.connectionIDLength

		if ut.connectionIDLength == 0 && ut.connectionIDGenerator == nil {
			ut.connectionIDGenerator = zeroConnectionIDGenerator{}
		}
	}

	ut.dedicatedConn = ut.connectionIDGenerator != nil && ut.connectionIDGenerator.ConnectionIDLen() == 0

	if settings.datagrams != nil {
		datagrams := *settings.datagrams
		ut.datagrams = &datagrams
	}

	if settings.streamPriority != nil {
		priority := *settings.streamPriority
		ut.streamPriority = &priority
	}

	snapshot := *settings
	snapshot.clientHandshake = settings.clientHandshake.Clone()
	ut.configureHandshake = snapshot.configureClientHandshake
	ut.fallbackTransport = c.GetTransport()

	switch base := ut.fallbackTransport.(type) {
	case *http.Transport:
		ut.requestProxy = base.Proxy
		if selectProxy := base.Proxy; selectProxy != nil {
			base.Proxy = func(req *http.Request) (*url.URL, error) {
				if selected, ok := req.Context().Value(tlsProxyKey{}).(proxySelection); ok {
					return selected.url, nil
				}
				return selectProxy(req)
			}
		}
	case *roundtripper:
		ut.requestProxy = base.requestProxy
	}

	if settings.discovery {
		if base, ok := ut.fallbackTransport.(*http.Transport); ok && base.DialTLSContext == nil {
			base.DialContext = tcpBindingDial(base.DialContext)
			base.DialTLSContext = ut.dialTCPWithECH(base)
		}
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

	if settings.discovery && !builder.forceHTTP3 {
		lookup := settings.httpsRecordsLookup
		if ut.proxy != "" {
			lookup = nil
		} else if lookup == nil {
			lookup = httpsLookupForResolver(ut.dialer.Resolver)
		}

		ut.discovery = newAlternativeDiscovery(
			lookup,
			settings.alternativeServiceBackoff,
			settings.expireFailedAlternatives,
		)
	}

	if settings.connectionRacing || ut.discovery != nil {
		if base, ok := ut.fallbackTransport.(*http.Transport); ok &&
			(base.DisableKeepAlives || base.MaxIdleConnsPerHost < 0) {
			ut.Close()
			return nil, errors.New("HTTP/3 connection racing requires TCP keep-alives")
		}

		_, ok := ut.fallbackTransport.(connectionPreconnector)
		if !ok {
			ut.Close()
			return nil, errors.New("HTTP/3 connection racing requires a transport with Preconnect support")
		}

		policy := settings.connectionRacingPolicy

		if settings.tcpFallbackDelay != nil {
			delay := *settings.tcpFallbackDelay
			policy = func(ConnectionRacingInfo) time.Duration { return delay }
		}

		tcp := ut.preconnectTCP
		if ut.discovery != nil {
			tcp = ut.preconnectDiscoveredTCP
		}
		ut.racer = &connectionRace{policy: policy, quic: ut.http3tr.Preconnect, tcp: tcp}
	}

	return ut, nil
}

// initTransport initializes the underlying QUIC and HTTP/3 transports.
func (ut *uquicTransport) initTransport() error {
	config := cloneQUICConfig(ut.quicConfig)

	if config == nil {
		config = defaultQUICConfig()
	}

	if ut.configureHandshake != nil {
		if err := ut.configureHandshake(config); err != nil {
			return err
		}
	}

	if ut.datagrams != nil {
		config.EnableDatagrams = *ut.datagrams
	}

	enableDatagrams := ut.settings.Get(SETTINGS_H3_DATAGRAM).UnwrapOrDefault() == 1

	if enableDatagrams && !config.EnableDatagrams {
		return errors.New("HTTP/3 datagrams require QUICConfig.EnableDatagrams")
	}

	if config.ClientHandshake != nil {
		ut.receivePacketSize = int(config.ClientHandshake.MaxUDPPayloadSize)

		if config.ClientHandshake.OmitMaxUDPPayloadSize {
			ut.receivePacketSize = quic.MaxUDPReceivePacketSize
		}
	}

	headerLimit := ut.maxResponseHeaderBytes
	if headerLimit == 0 {
		headerLimit = _maxResponseHeaderBytes
	}

	if ut.proxy == "" && !ut.dedicatedConn && !ut.lazySharedQUIC {
		var err error
		ut.pconn, err = ut.createUDPPacketConn()
		if err != nil {
			return fmt.Errorf("create packet conn: %w", err)
		}

		ut.quictr = ut.newQUICTransport(ut.pconn)
	}

	ut.http3tr = &http3.Transport{
		QPACKConfig:            ut.qpackConfig.Clone(),
		WireConfig:             ut.wireConfig.Clone(),
		TLSClientConfig:        ut.tlsConfig,
		QUICConfig:             config,
		StreamPriority:         ut.streamPriority,
		EnableDatagrams:        enableDatagrams,
		DisableCompression:     ut.disableCompression,
		AdditionalSettings:     ut.settings,
		MaxResponseHeaderBytes: headerLimit,
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
) (connection *quic.Conn, err error) {
	defer func() {
		if ut.racer != nil && connection != nil && err == nil {
			ut.racer.observeQUIC(addr, connection)
		}
	}()

	target := addr
	var route alternativeRoute

	if candidate, ok := ctx.Value(alternativeRouteKey{}).(alternativeRoute); ok &&
		strings.EqualFold(candidate.origin, addr) {
		route = candidate
		target = route.address
		defer func() {
			if ut.discovery != nil {
				ut.discovery.result(route, err)
			}
		}()
	}

	host, _, _ := net.SplitHostPort(addr)
	if tlsCfg.ServerName == "" && host != "" && net.ParseIP(host) == nil {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.ServerName = host
	}

	if len(route.ech) > 0 {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.EncryptedClientHelloConfigList = append([]byte(nil), route.ech...)
		tlsCfg.MinVersion = tls.VersionTLS13
	}

	if ut.discovery != nil || ut.addressFallbackDelay > 0 {
		addresses, resolveErr := ut.resolveAddresses(ctx, target, route.hints)
		if resolveErr != nil {
			return nil, resolveErr
		}
		return ut.dialAddresses(ctx, addresses, tlsCfg, cfg)
	}

	resolved, err := ut.resolve(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution: %w", err)
	}

	if ut.proxy != "" {
		return ut.dialSOCKS5(ctx, resolved, tlsCfg, cfg)
	}

	return ut.dialDirect(ctx, resolved, tlsCfg, cfg)
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

	if ut.dedicatedConn || udpAddr.IP.To4() == nil {
		var packetConn net.PacketConn
		var err error

		if udpAddr.IP.To4() == nil {
			packetConn, err = net.ListenUDP("udp6", nil)
		} else {
			packetConn, err = ut.createUDPPacketConn()
		}

		if err != nil {
			return nil, err
		}

		return ut.dialOwnedPacketConn(ctx, packetConn, udpAddr, tlsCfg, cfg, ut.useEarlyData(ctx))
	}

	transport, err := ut.sharedQUICTransport()
	if err != nil {
		return nil, err
	}

	if ut.useEarlyData(ctx) {
		return transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}

	return transport.Dial(ctx, udpAddr, tlsCfg, cfg)
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
	if req == nil || req.URL == nil || req.URL.Host == "" {
		if req != nil && req.Body != nil {
			req.Body.Close()
		}

		return nil, errors.New("HTTP/3 requires a request URL and host")
	}

	// Environment or application-selected TCP proxies own this request's route.
	// Do not bypass them through direct UDP or local HTTPS-record discovery.
	if ut.proxy == "" && ut.requestProxy != nil {
		proxy, err := ut.requestProxy(req)
		if err != nil {
			if req.Body != nil {
				req.Body.Close()
			}

			return nil, err
		}

		req = withProxySelection(req, proxy)
		if proxy != nil {
			return ut.roundTripProxy(req)
		}
	}

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

	if ut.discovery != nil {
		if req.URL.Scheme != "https" || requiresTCPHTTP(req) {
			return ut.fallbackTransport.RoundTrip(req)
		}
		return ut.roundTripDiscovered(req)
	}

	if ut.racer != nil && req.URL.Scheme == "https" {
		return ut.roundTripRacing(req)
	}

	resp, err := ut.roundTripHTTP3(req)
	if err != nil {
		return ut.handleError(req, err)
	}

	return resp, nil
}

// Add the profile header to a private HTTP/3 attempt, so automatic protocol
// fallback and redirects do not inherit an authority from a previous attempt.
func (ut *uquicTransport) requestWithAltUsed(req *http.Request) *http.Request {
	if !ut.altUsed || req.URL.Host == "" {
		return req
	}

	for name := range req.Header {
		if strings.EqualFold(name, header.ALT_USED) {
			return req
		}
	}

	authority := req.URL.Host
	if ut.discovery != nil {
		origin, _ := raceAddress(req)
		ut.discovery.mu.Lock()
		if actual, ok := ut.discovery.actual[origin]; ok {
			authority = actual.address
		} else if route, ok := req.Context().Value(alternativeRouteKey{}).(alternativeRoute); ok {
			authority = route.address
		}

		ut.discovery.mu.Unlock()
	}

	if _, port, err := net.SplitHostPort(authority); err == nil && port == "443" {
		authority = strings.TrimSuffix(authority, ":443")
	}

	clone := *req
	clone.Header = req.Header.Clone()
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}

	clone.Header.Set(header.ALT_USED, authority)

	return &clone
}

// handleError attempts HTTP/2 fallback for recoverable HTTP/3 errors.
func (ut *uquicTransport) handleError(req *http.Request, err error) (*http.Response, error) {
	if _, local := errors.AsType[*http3.RequestPreparationError](err); local {
		return nil, err
	}

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
	if ut.racer != nil {
		ut.racer.close(true)
	}

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
	if ut.discovery != nil {
		ut.discovery.close()
	}
	if ut.racer != nil {
		ut.racer.close(false)
	}

	if ut.http3tr != nil {
		ut.http3tr.Close()
	}

	ut.sharedMu.Lock()
	ut.sharedClosed = true
	transport, socket := ut.quictr, ut.pconn
	ut.sharedMu.Unlock()
	if transport != nil {
		transport.Close()
	}
	if socket != nil {
		socket.Close()
	}

	if ut.fallbackTransport != nil {
		if c, ok := ut.fallbackTransport.(interface{ Close() error }); ok {
			c.Close()
		} else if c, ok := ut.fallbackTransport.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
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

	if _, ok := errors.AsType[*proxyUDPError](err); ok {
		return true
	}

	if _, ok := errors.AsType[*quic.ApplicationError](err); ok {
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

	if opErr, ok := errors.AsType[*net.OpError](err); ok {
		if opErr.Op == "dial" || opErr.Op == "write" || opErr.Op == "read" {
			return true
		}

		if errno, ok := errors.AsType[syscall.Errno](opErr.Err); ok {
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
