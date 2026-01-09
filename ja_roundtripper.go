package surf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/g/cell"
	"github.com/enetx/g/ref"
	"github.com/enetx/http"
	"github.com/enetx/http2"

	utls "github.com/enetx/utls"
)

// unifiedTransport is a transport that wraps both HTTP/1.1 and HTTP/2 transports.
// It can dynamically switch between HTTP/1.1 and HTTP/2 based on ALPN negotiation
// and connection success, and optionally reuses a single pre-established connection.
type unifiedTransport struct {
	http1tr  *http.Transport  // underlying HTTP/1.1 transport
	http2tr  *http2.Transport // underlying HTTP/2 transport
	useHTTP1 uint32           // atomic flag, 1 if HTTP/1.1 should be forced
}

// newUnifiedTransport creates a new unifiedTransport.
func newUnifiedTransport(http1tr *http.Transport, http2tr *http2.Transport) *unifiedTransport {
	return &unifiedTransport{
		http1tr:  http1tr,
		http2tr:  http2tr,
		useHTTP1: 1,
	}
}

// RoundTrip executes a single HTTP transaction, choosing between HTTP/1.1 and HTTP/2.
//
// It attempts the request via HTTP/2 first, unless HTTP/1.1 has been forced by a previous failure.
// If the HTTP/2 attempt fails and the request context is still valid, it falls back to HTTP/1.1.
//
// For requests with a body, fallback is only performed if req.GetBody is defined,
// allowing the transport to rewind the stream. Upon fallback, the transport is
// atomically marked to prefer HTTP/1.1 for all subsequent requests, and any
// idle HTTP/2 connections are closed to release resources.
func (u *unifiedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if atomic.LoadUint32(&u.useHTTP1) == 1 || u.http2tr == nil {
		return u.http1tr.RoundTrip(req)
	}

	resp, err := u.http2tr.RoundTrip(req)
	if err == nil {
		return resp, nil
	}

	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, fmt.Errorf("surf: HTTP/2 failed and cannot retry because req.GetBody is nil: %w", err)
		}

		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("surf: failed to restore body for fallback: %w", err)
		}

		req.Body = body
	}

	atomic.StoreUint32(&u.useHTTP1, 1)
	u.http2tr.CloseIdleConnections()

	return u.http1tr.RoundTrip(req)
}

func (u *unifiedTransport) CloseIdleConnections() {
	if u.http1tr != nil {
		u.http1tr.CloseIdleConnections()
	}

	if u.http2tr != nil {
		u.http2tr.CloseIdleConnections()
	}
}

// roundtripper is a higher-level wrapper around HTTP transports, providing
// caching of connections, TLS session resumption, and unified transport handling.
type roundtripper struct {
	transport          *http.Transport                                                 // underlying HTTP/1.1 transport
	clientSessionCache utls.ClientSessionCache                                         // optional TLS session cache for resumption
	ja                 *JA                                                             // JA (JA3/JA4) fingerprint config
	cachedTransports   *g.MapSafe[string, *cell.LazyCell[g.Result[http.RoundTripper]]] // cached transports per address
}

// newRoundTripper creates a new roundtripper wrapping the given base transport
// and using JA configuration.
func newRoundTripper(ja *JA, base http.RoundTripper) http.RoundTripper {
	transport, ok := base.(*http.Transport)
	if !ok {
		panic("surf: underlying transport must be *http.Transport")
	}

	rt := &roundtripper{
		transport:        transport,
		ja:               ja,
		cachedTransports: g.NewMapSafe[string, *cell.LazyCell[g.Result[http.RoundTripper]]](),
	}

	if ja.builder.cli.tlsConfig.ClientSessionCache != nil {
		rt.clientSessionCache = utls.NewLRUClientSessionCache(0)
	}

	return rt
}

// RoundTrip executes a single HTTP request using a cached transport or creating
// a new one for the target address and scheme.
func (rt *roundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := rt.address(req)
	scheme := g.String(req.URL.Scheme).Lower()
	entry := rt.cachedTransports.Entry(addr)

	// Lazily initialize a transport for this address
	cellOpt := entry.OrSetBy(func() *cell.LazyCell[g.Result[http.RoundTripper]] {
		return cell.NewLazy(func() g.Result[http.RoundTripper] {
			var (
				tr  http.RoundTripper
				err error
			)

			switch scheme {
			case "http":
				tr = rt.buildHTTP1Transport()
			case "https":
				tr, err = rt.buildHTTPSTransport(req.Context(), addr)
			default:
				err = fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
			}

			return g.ResultOf(tr, err)
		})
	})

	var cellRef *cell.LazyCell[g.Result[http.RoundTripper]]

	if cellOpt.IsSome() {
		cellRef = cellOpt.Some()
	} else {
		cellRef = entry.Get().Some()
	}

	initRes := cellRef.Force()

	if initRes.IsErr() {
		rt.cachedTransports.Delete(addr)
		return nil, initRes.Err()
	}

	tr := initRes.Ok()

	resp, err := tr.RoundTrip(req)
	if resp == nil && err == nil {
		return nil, fmt.Errorf("surf: transport %T returned <nil, nil> for %s", tr, req.URL)
	}

	return resp, err
}

// CloseIdleConnections closes all idle connections for cached transports
// and clears the cache.
func (rt *roundtripper) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }

	for _, lazy := range rt.cachedTransports.Iter() {
		if transport := lazy.Force(); transport.IsOk() {
			if ci, ok := transport.Ok().(closeIdler); ok {
				ci.CloseIdleConnections()
			}
		}
	}

	rt.cachedTransports.Clear()
}

// buildHTTPSTransport constructs a unified transport for HTTPS connections.
// It performs a TLS handshake using uTLS, applies JA fingerprint presets,
// and conditionally enables HTTP/2 if negotiated by the server.
// The returned transport switches between HTTP/1.1 and HTTP/2 if available.
func (rt *roundtripper) buildHTTPSTransport(ctx context.Context, addr string) (http.RoundTripper, error) {
	uconn, err := rt.tlsHandshake(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	defer uconn.Close()

	useHTTP2 := uconn.ConnectionState().NegotiatedProtocol == "h2"

	var http2tr *http2.Transport
	if useHTTP2 {
		http2tr = rt.buildHTTP2Transport()
	}

	u := newUnifiedTransport(rt.buildHTTP1Transport(), http2tr)

	if http2tr != nil {
		atomic.StoreUint32(&u.useHTTP1, 0)
	}

	return u, nil
}

// dialTLSHTTP2 wraps dialTLS for HTTP/2 transport.
func (rt *roundtripper) dialTLSHTTP2(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	return rt.dialTLS(ctx, network, addr)
}

// dialTLS performs TLS handshake using the underlying transport.
func (rt *roundtripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	return rt.tlsHandshake(ctx, network, addr)
}

// tlsHandshake performs a full TLS handshake using uTLS, applying JA fingerprint
// presets and optionally enabling session resumption.
func (rt *roundtripper) tlsHandshake(ctx context.Context, network, addr string) (*utls.UConn, error) {
	timeout := rt.transport.TLSHandshakeTimeout
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

	rawConn, err := rt.transport.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	spec := rt.ja.getSpec()
	if spec.IsErr() {
		rawConn.Close()
		return nil, spec.Err()
	}

	if rt.ja.builder.forceHTTP1 {
		setAlpnProtocolToHTTP1(ref.Of(spec.Ok()))
	}

	config := &utls.Config{
		ServerName:             host,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		OmitEmptyPsk:           true,
		KeyLogWriter:           rt.ja.builder.cli.tlsConfig.KeyLogWriter,
	}

	if supportsResumption(spec.Ok()) && rt.clientSessionCache != nil {
		config.ClientSessionCache = rt.clientSessionCache
		config.PreferSkipResumptionOnNilExtension = true
		config.SessionTicketsDisabled = false
	}

	uconn := utls.UClient(rawConn, config, utls.HelloCustom)
	if err = uconn.ApplyPreset(ref.Of(spec.Ok())); err != nil {
		uconn.Close()
		return nil, err
	}

	if err = uconn.HandshakeContext(ctx); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("uTLS.HandshakeContext() error: %+v", err)
	}

	return uconn, nil
}

// address returns the host:port string for a request, using default ports if missing.
func (rt *roundtripper) address(req *http.Request) string {
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

// buildHTTP1Transport clones the underlying HTTP/1.1 transport and wraps DialTLS.
func (rt *roundtripper) buildHTTP1Transport() *http.Transport {
	if rt.transport == nil {
		return nil
	}

	t := rt.transport.Clone()
	t.DialTLSContext = rt.dialTLS

	return t
}

// buildHTTP2Transport builds a new HTTP/2 transport using settings from builder.
func (rt *roundtripper) buildHTTP2Transport() *http2.Transport {
	t := new(http2.Transport)

	t.DialTLSContext = rt.dialTLSHTTP2
	t.DisableCompression = rt.transport.DisableCompression
	t.IdleConnTimeout = rt.transport.IdleConnTimeout
	t.TLSClientConfig = rt.transport.TLSClientConfig

	if rt.ja.builder.http2settings != nil {
		h := rt.ja.builder.http2settings

		appendSetting := func(id http2.SettingID, val uint32) {
			if val != 0 || (id == http2.SettingEnablePush && h.usePush) {
				t.Settings = append(t.Settings, http2.Setting{ID: id, Val: val})
			}
		}

		settings := [...]struct {
			id  http2.SettingID
			val uint32
		}{
			{http2.SettingHeaderTableSize, h.headerTableSize},
			{http2.SettingEnablePush, h.enablePush},
			{http2.SettingMaxConcurrentStreams, h.maxConcurrentStreams},
			{http2.SettingInitialWindowSize, h.initialWindowSize},
			{http2.SettingMaxFrameSize, h.maxFrameSize},
			{http2.SettingMaxHeaderListSize, h.maxHeaderListSize},
		}

		for _, s := range settings {
			appendSetting(s.id, s.val)
		}

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

// supportsResumption checks if a ClientHelloSpec supports TLS session resumption.
func supportsResumption(spec utls.ClientHelloSpec) bool {
	var (
		hasSessionTicket bool
		hasPskModes      bool
		hasPreSharedKey  bool // includes real and fake PSK extensions
	)

	for _, ext := range spec.Extensions {
		switch ext.(type) {
		case *utls.SessionTicketExtension:
			hasSessionTicket = true
		case *utls.PSKKeyExchangeModesExtension:
			hasPskModes = true
		case *utls.UtlsPreSharedKeyExtension, *utls.FakePreSharedKeyExtension:
			hasPreSharedKey = true
		}
	}

	// If any TLS 1.3 PSK-related extensions are present,
	// session resumption is considered valid only when all required
	// TLS 1.3 resumption indicators are present simultaneously.
	if hasPskModes || hasPreSharedKey {
		return hasSessionTicket && hasPskModes && hasPreSharedKey
	}

	// Otherwise, fall back to TLS 1.2 semantics where the presence of
	// SessionTicketExtension alone indicates support for session resumption.
	return hasSessionTicket
}

// setAlpnProtocolToHTTP1 modifies the given ClientHelloSpec to prefer HTTP/1.1
// by updating or adding the ALPN extension.
func setAlpnProtocolToHTTP1(utlsSpec *utls.ClientHelloSpec) {
	for _, ext := range utlsSpec.Extensions {
		if alpns, ok := ext.(*utls.ALPNExtension); ok {
			if i := slices.Index(alpns.AlpnProtocols, "h2"); i != -1 {
				alpns.AlpnProtocols = slices.Delete(alpns.AlpnProtocols, i, i+1)
			}

			if !slices.Contains(alpns.AlpnProtocols, "http/1.1") {
				alpns.AlpnProtocols = append(alpns.AlpnProtocols, "http/1.1")
			}

			return
		}
	}

	// Add new ALPN extension if not present
	utlsSpec.Extensions = append(utlsSpec.Extensions, &utls.ALPNExtension{
		AlpnProtocols: []string{"http/1.1"},
	})
}
