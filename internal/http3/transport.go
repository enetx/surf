package h3transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/internal/connrace"
	"github.com/enetx/surf/internal/echretry"
	quictransport "github.com/enetx/surf/internal/quic"
	"github.com/enetx/surf/profiles"
)

// Transport implements http.RoundTripper with HTTP/3 support.
// It provides SOCKS5 proxy compatibility and automatic fallback to HTTP/2
// when HTTP/3 is unavailable or for non-SOCKS5 proxies.
type Transport struct {
	rttHistory             *rttHistory
	Fallback               http.RoundTripper
	discovery              *alternativeDiscovery
	racer                  *connrace.Racer
	http3tr                *http3.Transport
	quicDialer             *quictransport.Dialer
	requestProxy           func(*http.Request) (*url.URL, error)
	protocolHeaders        func(*http.Request, int)
	tlsConfig              *tls.Config
	settings               g.MapOrd[uint64, uint64]
	quicConfig             *quic.Config
	qpackConfig            *http3.QPACKConfig
	wireConfig             *http3.WireConfig
	streamPriority         *http3.StreamPriority
	configureHandshake     func(*quic.Config) error
	maxResponseHeaderBytes int
	datagrams              *bool
	disableCompression     bool
	altUsed                bool
	earlyData              bool
	forceHTTP3             bool
	tcpVersion             int
}

// New snapshots settings and builds HTTP/3 with its existing TCP fallback.
func New(settings Options) (*Transport, error) {
	if settings.TCPVersion == 0 {
		if err := settings.validateQUICConfig(); err != nil {
			return nil, err
		}
	}

	ut := &Transport{
		protocolHeaders:        settings.ProtocolHeaders,
		qpackConfig:            settings.QPACKConfig.Clone(),
		wireConfig:             settings.WireConfig.Clone(),
		altUsed:                settings.AltUsed,
		earlyData:              settings.EarlyData,
		forceHTTP3:             settings.ForceHTTP3,
		tcpVersion:             settings.TCPVersion,
		tlsConfig:              settings.TLSConfig.Clone(),
		settings:               settings.Settings.Clone(),
		quicConfig:             quictransport.CloneConfig(settings.QUICConfig),
		maxResponseHeaderBytes: settings.MaxResponseHeaderBytes,
		disableCompression:     settings.DisableCompression,
		quicDialer: &quictransport.Dialer{
			Proxy:                 settings.Proxy,
			NetDialer:             settings.Dialer,
			AddressFallbackDelay:  settings.AddressFallbackDelay,
			Lazy:                  settings.Discovery && !settings.ForceHTTP3,
			ConnectionIDGenerator: settings.ConnectionIDGenerator,
		},
	}

	if settings.ConnectionIDLength != nil {
		ut.quicDialer.ConnectionIDLength = *settings.ConnectionIDLength

		if ut.quicDialer.ConnectionIDLength == 0 && ut.quicDialer.ConnectionIDGenerator == nil {
			ut.quicDialer.ConnectionIDGenerator = quictransport.ZeroConnectionIDGenerator{}
		}
	}

	if settings.CachedRTTParameter != 0 && settings.Proxy == "" {
		ut.rttHistory = &rttHistory{
			parameter: settings.CachedRTTParameter,
			minimum:   settings.MinimumInitialRTT,
			maximum:   settings.MaximumInitialRTT,
		}
	}

	ut.quicDialer.DedicatedConn = ut.quicDialer.ConnectionIDGenerator != nil &&
		ut.quicDialer.ConnectionIDGenerator.ConnectionIDLen() == 0

	if ut.quicDialer.NetDialer == nil {
		ut.quicDialer.NetDialer = new(net.Dialer)
	}

	if settings.Datagrams != nil {
		datagrams := *settings.Datagrams
		ut.datagrams = &datagrams
	}

	if settings.StreamPriority != nil {
		priority := *settings.StreamPriority
		ut.streamPriority = &priority
	}

	snapshot := settings
	snapshot.ClientHandshake = settings.ClientHandshake.Clone()
	ut.configureHandshake = snapshot.configureClientHandshake
	ut.Fallback = settings.Fallback
	ut.requestProxy = settings.RequestProxy

	if base, ok := ut.Fallback.(*http.Transport); ok {
		ut.requestProxy = base.Proxy
		if selectProxy := base.Proxy; selectProxy != nil {
			base.Proxy = func(req *http.Request) (*url.URL, error) {
				if selected, ok := req.Context().Value(tlsProxyKey{}).(proxySelection); ok {
					return selected.url, nil
				}
				return selectProxy(req)
			}
		}
	}

	if settings.Discovery {
		if base, ok := ut.Fallback.(*http.Transport); ok && base.DialTLSContext == nil {
			base.DialContext = tcpBindingDial(
				base.DialContext,
				ut.quicDialer.NetDialer.FallbackDelay,
				settings.UseResolvedTCPAddresses,
			)
			base.DialTLSContext = ut.dialTCPWithECH(base)
		}
	}

	if ut.quicDialer.Proxy != "" && !isSOCKS5Proxy(ut.quicDialer.Proxy) {
		if ut.Fallback == nil {
			return nil, errors.New("HTTP/3 requires SOCKS5 proxy for UDP relay")
		}

		return ut, nil
	}

	if settings.Discovery {
		lookup := settings.HTTPSRecordsLookup
		if ut.quicDialer.Proxy != "" {
			lookup = nil
		} else if lookup == nil {
			lookup = httpsLookupForResolver(ut.quicDialer.NetDialer.Resolver)
		}

		ut.discovery = newAlternativeDiscovery(
			lookup,
			settings.AlternativeServiceBackoff,
			settings.ExpireFailedAlternatives,
		)
		ut.discovery.tcpVersion = settings.TCPVersion
		if settings.HTTPSRecordsLookup == nil && ut.quicDialer.Proxy == "" &&
			(settings.TCPVersion == 0 || settings.UseResolvedTCPAddresses) {
			ut.discovery.httpsWait = settings.HTTPSRecordsWait
			ut.discovery.addressLookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
				resolver := ut.quicDialer.NetDialer.Resolver
				if resolver == nil {
					resolver = net.DefaultResolver
				}
				return resolver.LookupIPAddr(ctx, host)
			}

			ut.quicDialer.LookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
				return lookupResolvedAddresses(ctx, host, ut.quicDialer.NetDialer.Resolver)
			}
		}
	}

	// Forced TCP keeps its HTTP transports and DNS/TLS metadata, without
	// validating unused QUIC settings, opening UDP or starting an H3 race.
	if settings.TCPVersion != 0 {
		return ut, nil
	}

	if err := ut.initTransport(); err != nil {
		return nil, err
	}

	// Keep the direct forced-H3 address policy. Discovery routes still pass
	// their hints to Dial; explicit address racing uses AddressFallbackDelay.
	ut.quicDialer.ResolveAll = ut.discovery != nil && !settings.ForceHTTP3

	if settings.ConnectionRacing || ut.discovery != nil && !settings.ForceHTTP3 {
		if base, ok := ut.Fallback.(*http.Transport); ok &&
			(base.DisableKeepAlives || base.MaxIdleConnsPerHost < 0) {
			ut.Close()
			return nil, errors.New("HTTP/3 connection racing requires TCP keep-alives")
		}

		_, ok := ut.Fallback.(Preconnector)
		if !ok {
			ut.Close()
			return nil, errors.New("HTTP/3 connection racing requires a transport with Preconnect support")
		}

		policy := settings.ConnectionRacingPolicy

		if settings.TCPFallbackDelay != nil {
			delay := *settings.TCPFallbackDelay
			policy = func(profiles.ConnectionRacingInfo) time.Duration { return delay }
		}

		tcp := ut.preconnectTCP
		if ut.discovery != nil {
			tcp = ut.preconnectDiscoveredTCP
		}

		ut.racer = connrace.New(policy, ut.http3tr.Preconnect, func(req *http.Request) (bool, error) {
			var http1 bool
			req = req.WithContext(context.WithValue(req.Context(), preparedTCPHTTP1Key{}, &http1))
			err := tcp(req)

			return http1, err
		})
	}

	return ut, nil
}

// initTransport initializes the underlying QUIC and HTTP/3 transports.
func (ut *Transport) initTransport() error {
	config := quictransport.CloneConfig(ut.quicConfig)

	if config == nil {
		config = quictransport.DefaultConfig()
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
		ut.quicDialer.ReceivePacketSize = int(config.ClientHandshake.MaxUDPPayloadSize)

		if config.ClientHandshake.OmitMaxUDPPayloadSize {
			ut.quicDialer.ReceivePacketSize = quic.MaxUDPReceivePacketSize
		}
	}

	headerLimit := ut.maxResponseHeaderBytes
	if headerLimit == 0 {
		headerLimit = DefaultMaxResponseHeaderBytes
	}

	if err := ut.quicDialer.Init(); err != nil {
		return err
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

// RoundTrip executes an HTTP/3 request with automatic fallback to HTTP/2.
func (ut *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil || req.URL.Host == "" {
		if req != nil && req.Body != nil {
			req.Body.Close()
		}

		return nil, errors.New("HTTP/3 requires a request URL and host")
	}

	// Environment or application-selected TCP proxies own this request's route.
	// Do not bypass them through direct UDP or local HTTPS-record discovery.
	if ut.quicDialer.Proxy == "" && ut.requestProxy != nil {
		proxy, err := ut.requestProxy(req)
		if err != nil {
			if req.Body != nil {
				req.Body.Close()
			}

			return nil, err
		}

		req = WithProxySelection(req, proxy)
		if proxy != nil {
			return ut.roundTripProxy(req)
		}
	}

	if ut.quicDialer.Proxy != "" && !isSOCKS5Proxy(ut.quicDialer.Proxy) {
		if ut.Fallback != nil {
			return ut.Fallback.RoundTrip(req)
		}

		return nil, errors.New("non-SOCKS5 proxy requires HTTP/2 fallback")
	}

	if ut.tcpVersion != 0 && ut.discovery != nil && req.URL.Scheme == "https" && !requiresTCPHTTP(req) {
		return ut.roundTripDiscovered(req)
	}

	if ut.http3tr == nil {
		if ut.Fallback != nil {
			return ut.Fallback.RoundTrip(req)
		}

		return nil, errors.New("no transport available")
	}

	if req.URL.Scheme == "" {
		req = cloneRequestWithScheme(req, "https")
	}

	if ut.discovery != nil {
		if req.URL.Scheme != "https" || requiresTCPHTTP(req) {
			return ut.Fallback.RoundTrip(req)
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
func (ut *Transport) requestWithAltUsed(req *http.Request) *http.Request {
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
		} else if route, ok := req.Context().Value(alternativeRouteKey{}).(alternativeRoute); ok && route.address != "" {
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
func (ut *Transport) handleError(req *http.Request, err error) (*http.Response, error) {
	if _, local := errors.AsType[*http3.RequestPreparationError](err); local {
		return nil, err
	}

	if req.Context().Err() != nil {
		return nil, err
	}

	if !isHTTP3UnsupportedError(err) || ut.Fallback == nil {
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

	return ut.Fallback.RoundTrip(req)
}

// CloseIdleConnections closes idle connections while keeping the transport usable.
func (ut *Transport) CloseIdleConnections() {
	if ut.racer != nil {
		ut.racer.Close(true)
	}

	if ut.http3tr != nil {
		ut.http3tr.CloseIdleConnections()
	}

	if ut.Fallback != nil {
		if c, ok := ut.Fallback.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}

// Close shuts down the transport and releases all resources.
func (ut *Transport) Close() error {
	if ut.rttHistory != nil {
		ut.rttHistory.close()
	}

	if ut.discovery != nil {
		ut.discovery.close()
	}

	if ut.racer != nil {
		ut.racer.Close(false)
	}

	if ut.http3tr != nil {
		ut.http3tr.Close()
	}

	ut.quicDialer.Close()

	if ut.Fallback != nil {
		if c, ok := ut.Fallback.(interface{ Close() error }); ok {
			c.Close()
		} else if c, ok := ut.Fallback.(interface{ CloseIdleConnections() }); ok {
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

	if _, ok := errors.AsType[*quictransport.ProxyUDPError](err); ok {
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

type http3RequireHandshakeKey struct{}

func (ut *Transport) roundTripHTTP3(req *http.Request) (*http.Response, error) {
	attempt := ut.requestWithAltUsed(WithProtocolHeaders(req, ut.protocolHeaders, 3))

	eligible := ut.earlyData && (req.Body == nil || req.Body == http.NoBody) &&
		(req.Method == http.MethodGet || req.Method == http.MethodHead)
	if !eligible {
		if ut.earlyData {
			attempt = attempt.WithContext(context.WithValue(attempt.Context(), http3RequireHandshakeKey{}, true))
		}

		return ut.http3tr.RoundTrip(attempt)
	}

	clone := *attempt

	if req.Method == http.MethodGet {
		clone.Method = http3.MethodGet0RTT
	} else {
		clone.Method = http3.MethodHead0RTT
	}

	response, err := ut.http3tr.RoundTrip(&clone)
	if config := echretry.Configs(err); len(config) > 0 && req.Context().Err() == nil {
		// Only bodyless GET/HEAD can reach this branch. Reconnect once with
		// authenticated retry_configs and wait for the complete handshake.
		ctx := echretry.WithConfig(attempt.Context(), config)
		ctx = context.WithValue(ctx, http3RequireHandshakeKey{}, true)
		return ut.http3tr.RoundTrip(attempt.WithContext(ctx))
	}

	if !errors.Is(err, quic.Err0RTTRejected) && (err != nil || response.StatusCode != http.StatusTooEarly) {
		return response, err
	}

	if response != nil {
		response.Body.Close()
	}

	// Retry at most once, after the handshake. Retain the original method and
	// request context; a new dial must not attempt early data either.
	retry := attempt.WithContext(context.WithValue(attempt.Context(), http3RequireHandshakeKey{}, true))

	return ut.http3tr.RoundTrip(retry)
}

func (ut *Transport) useEarlyData(ctx context.Context) bool {
	required, _ := ctx.Value(http3RequireHandshakeKey{}).(bool)
	return ut.earlyData && !required
}
