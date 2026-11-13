package surf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/http/httptrace"
	"github.com/enetx/surf/internal/echretry"
	h3transport "github.com/enetx/surf/internal/http3"
	"github.com/enetx/surf/internal/quictls"
	"github.com/enetx/surf/internal/tlsstate"
	utls "github.com/enetx/utls"
)

// roundtripper is a higher-level wrapper around HTTP transports, providing
// TLS session resumption and protocol selection.
type roundtripper struct {
	http1tr            *http.Transport
	http1trFallback    *http.Transport
	http2tr            *http2.Transport
	clientSessionCache utls.ClientSessionCache
	ja                 *JA
	protocolHeaders    requestHeadersPolicy
	requestProxy       func(*http.Request) (*url.URL, error)
	http2settings      *HTTP2Settings
	http1Required      *http1RequiredCache
	proxyMu            sync.Mutex
	proxyTransports    map[string]*roundtripper
}

// newRoundTripper creates a new roundtripper wrapping the given base transport
// and using JA configuration.
func newRoundTripper(ja *JA, base http.RoundTripper) http.RoundTripper {
	http1tr, ok := base.(*http.Transport)
	if !ok {
		panic("surf: underlying transport must be *http.Transport")
	}

	// Clone the base configuration before attaching the JA protocol adapter.
	// A prior HTTP2Settings middleware may already own a transport registration.
	http1tr = http1tr.Clone()

	rt := &roundtripper{
		http1tr:         http1tr,
		ja:              ja,
		protocolHeaders: ja.builder.protocolHeaders,
		requestProxy:    http1tr.Proxy,
	}

	rt.configureProxy()

	source := ja.builder.cli.tlsConfig
	if !source.SessionTicketsDisabled {
		cache := source.ClientSessionCache
		if owned, ok := cache.(*defaultSessionCache); ok {
			cache = owned.ClientSessionCache
		}

		if cache != nil {
			rt.clientSessionCache = quictls.TCPSessionCache(cache)
		}
	}

	if h := ja.builder.http2settings; h != nil {
		snapshot := *h
		snapshot.hpack = h.hpack.Clone()
		snapshot.priorityFrames = slices.Clone(h.priorityFrames)
		rt.http2settings = &snapshot
	}

	capacity := ja.http1RequiredCache

	if rt.http2settings != nil && rt.http2settings.http1RequiredCacheSet {
		capacity = rt.http2settings.http1RequiredCache
	}

	if capacity > 0 {
		rt.http1Required = &http1RequiredCache{capacity: capacity}
	}

	rt.configureTransports(!ja.builder.forceHTTP1)

	return rt
}

func (rt *roundtripper) configureTransports(enableHTTP2 bool) {
	rt.http1tr.DialTLSContext = rt.dialTLS
	rt.http1tr.PrepareHeaders = rt.protocolHeaders

	if enableHTTP2 {
		if rt.http1tr.Protocols != nil {
			rt.http1tr.Protocols.SetHTTP1(true)
		}
		rt.http2tr = rt.buildHTTP2Transport()
	}

	rt.http1trFallback = rt.http1tr.Clone()
	rt.http1trFallback.DialTLSContext = rt.dialTLSHTTP1
	rt.http1trFallback.Protocols = new(http.Protocols)
	rt.http1trFallback.Protocols.SetHTTP1(true)
}

// RoundTrip executes a single HTTP request using cached transports.
func (rt *roundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	scheme := strings.ToLower(req.URL.Scheme)

	switch scheme {
	case "http":
		// Plain HTTP always uses HTTP/1.1 (HTTP/2 requires TLS)
		return rt.http1tr.RoundTrip(req)
	case "https":
		var err error
		req, err = rt.prepareProxy(req)
		if err != nil {
			if req.Body != nil {
				req.Body.Close()
			}

			return nil, err
		}

		child, err := rt.proxyTransport(req)
		if err != nil {
			if req.Body != nil {
				req.Body.Close()
			}

			return nil, err
		}

		if child != nil {
			return child.RoundTrip(req)
		}
		return rt.handleHTTPSRequest(req)
	default:
		return nil, fmt.Errorf("invalid URL scheme: %s", req.URL.Scheme)
	}
}

// handleHTTPSRequest handles HTTPS requests with optional HTTP/2 support.
// Reuses pre-built transports to avoid allocations.
func (rt *roundtripper) handleHTTPSRequest(req *http.Request) (*http.Response, error) {
	if h3transport.PreparedHTTP1(req.Context()) || rt.requiresHTTP1(req) {
		return rt.http1trFallback.RoundTrip(req)
	}

	// If HTTP/1 is forced, use it directly
	if rt.http2tr == nil {
		return rt.http1tr.RoundTrip(req)
	}

	// Like Chrome, only resend after a reused connection closes without any
	// response, including informational headers. Keep the caller's trace hooks.
	var reused, receivedInformational atomic.Bool

	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			secure, ok := info.Conn.(*profileTLSConn)
			reused.Store(info.Reused && ok && secure.ConnectionState().NegotiatedProtocol == "h2")
			receivedInformational.Store(false)
		},
		Got1xxResponse: func(_ int, _ textproto.MIMEHeader) error {
			receivedInformational.Store(true)
			return nil
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// Try HTTP/2 first
	resp, err := rt.http2tr.RoundTrip(req)
	if err == nil {
		return resp, nil
	}

	if reused.Load() && !receivedInformational.Load() && connClosedBeforeResponse(err) {
		// The server closed a reused HTTP/2 connection before it answered this request.
		// Imperva does this to every request still in flight after it answers one with a block
		// page: close_notify and FIN, no GOAWAY. Chrome sends such a request once more on a new
		// connection, and so does surf. The closed connection is no longer in the pool.
		if err := rewindBody(req, err); err != nil {
			return nil, err
		}

		resp, err = rt.http2tr.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
	}

	h2Err := err

	if !wantsHTTP1(h2Err) {
		return nil, h2Err
	}

	if err := rewindBody(req, h2Err); err != nil {
		return nil, err
	}

	// Retry with HTTP/1.1
	resp, err = rt.http1trFallback.RoundTrip(req)
	if err != nil {
		return nil, &ErrHTTP2Fallback{HTTP2: h2Err, HTTP1: err}
	}

	return resp, nil
}

// rewindBody prepares req to be sent again after the failed attempt err.
func rewindBody(req *http.Request, err error) error {
	if ctxErr := req.Context().Err(); ctxErr != nil {
		return ctxErr
	}

	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	if req.GetBody == nil {
		return fmt.Errorf("surf: cannot send the request again because req.GetBody is nil: %w", err)
	}

	body, bodyErr := req.GetBody()
	if bodyErr != nil {
		return fmt.Errorf("surf: failed to restore body to send the request again: %w", bodyErr)
	}

	req.Body = body

	return nil
}

// tlsDialError marks a failure to establish TLS, so that it is never mistaken for
// a connection the server closed after the handshake. A proxy tunnel can fail its own
// handshake with io.ErrUnexpectedEOF too.
type tlsDialError struct{ err error }

func (e *tlsDialError) Error() string { return e.err.Error() }
func (e *tlsDialError) Unwrap() error { return e.err }

// connClosedBeforeResponse classifies closure and reset errors returned before final
// HTTP/2 response headers. The caller separately checks reuse and informational responses.
func connClosedBeforeResponse(err error) bool {
	if _, ok := errors.AsType[*tlsDialError](err); ok {
		return false
	}

	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
}

// wantsHTTP1 reports an explicit HTTP_1_1_REQUIRED response from HTTP/2.
// ALPN selection is handled by the normal transport on the selected connection.
func wantsHTTP1(err error) bool {
	if se, ok := errors.AsType[http2.StreamError](err); ok {
		return se.Code == http2.ErrCodeHTTP11Required
	}

	if ga, ok := errors.AsType[http2.GoAwayError](err); ok {
		return ga.ErrCode == http2.ErrCodeHTTP11Required
	}

	// Native handling returns an untyped error when GOAWAY rejects the first
	// request. Match its complete message; other codes must not enable fallback.
	const firstStreamHTTP1Required = "http2: Transport received GOAWAY from server ErrCode:HTTP_1_1_REQUIRED"

	for err != nil {
		if err.Error() == firstStreamHTTP1Required {
			return true
		}

		err = errors.Unwrap(err)
	}

	return false
}

// CloseIdleConnections closes all idle connections.
func (rt *roundtripper) CloseIdleConnections() {
	rt.closeProxyIdleConnections()
	if rt.http1tr != nil {
		rt.http1tr.CloseIdleConnections()
	}

	if rt.http1trFallback != nil {
		rt.http1trFallback.CloseIdleConnections()
	}

	if rt.http2tr != nil {
		rt.http2tr.CloseIdleConnections()
	}
}

// buildHTTP2Transport builds a new HTTP/2 transport using the completed builder snapshot.
func (rt *roundtripper) buildHTTP2Transport() *http2.Transport {
	t, err := http2.ConfigureTransports(rt.http1tr)
	if err != nil {
		panic(err)
	}

	t.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		return rt.dialTLS(ctx, network, addr)
	}

	t.DisableCompression = rt.http1tr.DisableCompression
	t.IdleConnTimeout = rt.http1tr.IdleConnTimeout
	t.PingTimeout = _http2PingTimeout
	t.ReadIdleTimeout = _http2ReadIdleTimeout
	t.WriteByteTimeout = _http2WriteByteTimeout
	if rt.http1Required != nil {
		t.ConnectionErrorPolicy = rt.connectionErrorPolicy
	}

	if rt.http2settings != nil {
		h := rt.http2settings
		t.HPACK = h.hpack.Clone()
		t.MaxEncoderHeaderTableSize = h.maxEncoderHeaderTableSize
		t.HeaderPriority = h.headerPriority
		t.ChainStreamDependencies = h.chainStreamDependencies
		t.StreamReceiveWindow = h.streamReceiveWindow
		t.ReceiveWindowUpdatePolicy = h.receiveWindowUpdatePolicy

		// Pre-allocate settings slice to avoid multiple allocations
		t.Settings = make([]http2.Setting, 0, 7)

		appendSetting := func(id http2.SettingID, val uint32) {
			if val != 0 || (id == http2.SettingEnablePush && h.usePush) {
				t.Settings = append(t.Settings, http2.Setting{ID: id, Val: val})
			}
		}

		appendSetting(http2.SettingHeaderTableSize, h.headerTableSize)
		appendSetting(http2.SettingEnablePush, h.enablePush)
		appendSetting(http2.SettingMaxConcurrentStreams, h.maxConcurrentStreams)
		appendSetting(http2.SettingInitialWindowSize, h.initialWindowSize)
		appendSetting(http2.SettingMaxFrameSize, h.maxFrameSize)
		appendSetting(http2.SettingMaxHeaderListSize, h.maxHeaderListSize)
		appendSetting(http2.SettingNoRFC7540Priorities, h.noRFC7540Priorities)

		if h.initialStreamID != 0 {
			t.StreamID = h.initialStreamID
		}

		if h.connectionFlow != 0 {
			t.ConnectionFlow = h.connectionFlow
		}

		if !h.priorityParam.IsZero() {
			t.PriorityParam = h.priorityParam
		}

		if h.priorityFrames != nil {
			t.PriorityFrames = h.priorityFrames
		}
	}

	return t
}

// dialTLS retains the connection for its negotiated protocol. Normal HTTP/1
// selection does not change subsequent ClientHellos or require body replay.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_stream_pool_attempt_manager.cc
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpConnection.cpp
func (rt *roundtripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	var key string
	if rt.http1Required != nil {
		key = tlsOrigin(addr)
	}

	conn, err := rt.tlsHandshake(ctx, network, addr, rt.http1Required.contains(key))
	if err != nil {
		return nil, &tlsDialError{err}
	}

	switch protocol := conn.ConnectionState().NegotiatedProtocol; protocol {
	case "", "http/1.1", "h2":
		return &profileTLSConn{UConn: conn, origin: key}, nil
	default:
		conn.Close()
		return nil, &tlsDialError{fmt.Errorf("surf: unsupported negotiated ALPN %q", protocol)}
	}
}

// dialTLSHTTP1 performs TLS handshake using uTLS with HTTP/1.1 only ALPN.
// Used for fallback when HTTP/2 connection fails.
func (rt *roundtripper) dialTLSHTTP1(ctx context.Context, network, addr string) (net.Conn, error) {
	return wrapProfileTLS(rt.tlsHandshake(ctx, network, addr, true))
}

// tlsHandshake performs a full TLS handshake using uTLS, applying JA fingerprint
// presets and optionally enabling session resumption.
func (rt *roundtripper) tlsHandshake(ctx context.Context, network, addr string, forceHTTP1 bool) (*utls.UConn, error) {
	timeout := rt.http1tr.TLSHandshakeTimeout
	if timeout > 0 {
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining < timeout {
				timeout = remaining
			}
		}

		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	uconn, err := rt.tlsHandshakeOnce(ctx, network, addr, forceHTTP1)

	if retry := echretry.Configs(err); len(retry) > 0 && ctx.Err() == nil {
		return rt.tlsHandshakeOnce(echretry.WithConfig(ctx, retry), network, addr, forceHTTP1)
	}

	return uconn, err
}

func (rt *roundtripper) tlsHandshakeOnce(
	ctx context.Context,
	network, addr string,
	forceHTTP1 bool,
) (*utls.UConn, error) {
	rawConn, err := rt.http1tr.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	specr := rt.ja.getSpec()
	if specr.IsErr() {
		rawConn.Close()
		return nil, specr.Err()
	}

	spec := specr.Ok()

	// Apply HTTP/1 ALPN if forced
	if forceHTTP1 || rt.ja.builder.forceHTTP1 {
		setAlpnProtocolToHTTP1(&spec)
	}

	source := rt.ja.builder.cli.tlsConfig
	config := &utls.Config{
		ECHClientHelloInner: rt.ja.echInner,
		RootCAs:             source.RootCAs, Rand: source.Rand, Time: source.Time,
		VerifyPeerCertificate:          source.VerifyPeerCertificate,
		EncryptedClientHelloConfigList: slices.Clone(source.EncryptedClientHelloConfigList),
		ServerName:                     host,
		InsecureSkipVerify:             rt.ja.builder.cli.tlsConfig.InsecureSkipVerify,
		SessionTicketsDisabled:         true,
		OmitEmptyPsk:                   true,
		KeyLogWriter:                   rt.ja.builder.cli.tlsConfig.KeyLogWriter,
	}

	if source.ServerName != "" {
		config.ServerName = source.ServerName
	}

	if source.VerifyConnection != nil {
		config.VerifyConnection = func(s utls.ConnectionState) error { return source.VerifyConnection(tlsstate.FromUTLS(s)) }
	}

	if source.EncryptedClientHelloRejectionVerify != nil {
		config.EncryptedClientHelloRejectionVerify = func(s utls.ConnectionState) error {
			return source.EncryptedClientHelloRejectionVerify(tlsstate.FromUTLS(s))
		}
	}

	if ech := h3transport.ECHConfig(ctx); len(ech) > 0 {
		config.EncryptedClientHelloConfigList = slices.Clone(ech)
	}

	if retry := echretry.FromContext(ctx); len(retry) > 0 {
		config.EncryptedClientHelloConfigList = retry
	}

	if len(config.EncryptedClientHelloConfigList) > 0 {
		config.MinVersion = utls.VersionTLS13
		// With real ECH, uTLS takes inner ALPN from Config rather than the
		// outer extension. Preserve the selected profile and HTTP/1 fallback.
		for _, extension := range spec.Extensions {
			if alpn, ok := extension.(*utls.ALPNExtension); ok {
				config.NextProtos = slices.Clone(alpn.AlpnProtocols)
			}
		}
	}

	if supportsResumption(spec) && rt.clientSessionCache != nil && !source.SessionTicketsDisabled {
		config.ClientSessionCache = rt.clientSessionCache
		config.PreferSkipResumptionOnNilExtension = true
		config.SessionTicketsDisabled = false
	}

	uconn := utls.UClient(rawConn, config, utls.HelloCustom)
	if err = uconn.ApplyPreset(&spec); err != nil {
		uconn.Close()
		return nil, err
	}

	// Bind extensions to the cloned hello before uTLS loads a cached session.
	for _, extension := range uconn.Extensions {
		if binder, ok := extension.(interface{ BindClientHello(*utls.UConn) }); ok {
			binder.BindClientHello(uconn)
		}
	}

	if err = uconn.HandshakeContext(ctx); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("uTLS.HandshakeContext() error: %w", err)
	}

	return uconn, nil
}

// supportsResumption checks if a ClientHelloSpec supports TLS session resumption.
func supportsResumption(spec utls.ClientHelloSpec) bool {
	var (
		hasSessionTicket bool
		hasPskModes      bool
		hasPreSharedKey  bool
	)

	for _, ext := range spec.Extensions {
		switch ext.(type) {
		case utls.ISessionTicketExtension:
			hasSessionTicket = true
		case *utls.PSKKeyExchangeModesExtension:
			hasPskModes = true
		case *utls.UtlsPreSharedKeyExtension, *utls.FakePreSharedKeyExtension:
			hasPreSharedKey = true
		}
	}

	// Cache profiles that provide both ticket paths when TLS 1.3 is offered.
	// Templates without PSK, including the captured WebKit profile, keep full
	// handshakes while Session can still preserve HTTP cookies.
	if hasPskModes || hasPreSharedKey {
		return hasSessionTicket && hasPskModes && hasPreSharedKey
	}

	// Otherwise, fall back to TLS 1.2 semantics where the presence of
	// SessionTicketExtension alone indicates support for session resumption.
	return hasSessionTicket
}

// setAlpnProtocolToHTTP1 advertises HTTP/1.1 and removes application settings
// for protocols that are no longer offered.
func setAlpnProtocolToHTTP1(utlsSpec *utls.ClientHelloSpec) {
	utlsSpec.Extensions = slices.DeleteFunc(utlsSpec.Extensions, func(ext utls.TLSExtension) bool {
		switch ext.(type) {
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			return true
		}
		return false
	})

	for _, ext := range utlsSpec.Extensions {
		alpns, ok := ext.(*utls.ALPNExtension)
		if !ok {
			continue
		}

		filtered := alpns.AlpnProtocols[:0]
		hasHTTP1 := false

		for _, proto := range alpns.AlpnProtocols {
			if proto == "h2" {
				continue
			}

			if proto == "http/1.1" {
				hasHTTP1 = true
			}

			filtered = append(filtered, proto)
		}

		alpns.AlpnProtocols = filtered

		if !hasHTTP1 {
			alpns.AlpnProtocols = append(alpns.AlpnProtocols, "http/1.1")
		}

		return
	}

	utlsSpec.Extensions = append(utlsSpec.Extensions, &utls.ALPNExtension{
		AlpnProtocols: []string{"http/1.1"},
	})
}

// HTTP transports recognize the standard ConnectionState signature. Keep uTLS's
// methods available through embedding while translating only public state.
type profileTLSConn struct {
	*utls.UConn
	origin string // Original TLS destination, independent of request Host and proxy.
}

func (c *profileTLSConn) ConnectionState() tls.ConnectionState {
	return tlsstate.FromUTLS(c.UConn.ConnectionState())
}

func wrapProfileTLS(c *utls.UConn, err error) (net.Conn, error) {
	if err != nil {
		return nil, err
	}

	return &profileTLSConn{UConn: c}, nil
}
