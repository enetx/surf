package surf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http2"

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
}

// newRoundTripper creates a new roundtripper wrapping the given base transport
// and using JA configuration.
func newRoundTripper(ja *JA, base http.RoundTripper) http.RoundTripper {
	http1tr, ok := base.(*http.Transport)
	if !ok {
		panic("surf: underlying transport must be *http.Transport")
	}

	rt := &roundtripper{
		http1tr: http1tr,
		ja:      ja,
	}

	if ja.builder.cli.tlsConfig.ClientSessionCache != nil {
		rt.clientSessionCache = utls.NewLRUClientSessionCache(0)
	}

	rt.http1tr.DialTLSContext = rt.dialTLS
	rt.http1trFallback = http1tr.Clone()
	rt.http1trFallback.DialTLSContext = rt.dialTLSHTTP1

	if !ja.builder.forceHTTP1 {
		rt.http2tr = rt.buildHTTP2Transport()
	}

	return rt
}

// RoundTrip executes a single HTTP request.
// Optimized for parsing different sites (no per-request allocations).
func (rt *roundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	scheme := strings.ToLower(req.URL.Scheme)

	switch scheme {
	case "http":
		// Plain HTTP always uses HTTP/1.1 (HTTP/2 requires TLS)
		return rt.http1tr.RoundTrip(req)
	case "https":
		return rt.handleHTTPSRequest(req)
	default:
		return nil, fmt.Errorf("invalid URL scheme: %s", req.URL.Scheme)
	}
}

// handleHTTPSRequest handles HTTPS requests with optional HTTP/2 support.
// Reuses pre-built transports to avoid allocations.
func (rt *roundtripper) handleHTTPSRequest(req *http.Request) (*http.Response, error) {
	// If HTTP/1 is forced, use it directly
	if rt.http2tr == nil {
		return rt.http1tr.RoundTrip(req)
	}

	// Try HTTP/2 first
	resp, err := rt.http2tr.RoundTrip(req)
	if err == nil {
		return resp, nil
	}

	// HTTP/2 failed - fallback to HTTP/1.1
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	// Restore request body if needed for retry
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, fmt.Errorf("surf: HTTP/2 failed and cannot retry because req.GetBody is nil: %w", err)
		}

		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return nil, fmt.Errorf("surf: failed to restore body for fallback: %w", bodyErr)
		}
		req.Body = body
	}

	// Retry with HTTP/1.1
	return rt.http1trFallback.RoundTrip(req)
}

// CloseIdleConnections closes all idle connections.
func (rt *roundtripper) CloseIdleConnections() {
	if rt.http1tr != nil {
		rt.http1tr.CloseIdleConnections()
	}

	if rt.http2tr != nil {
		rt.http2tr.CloseIdleConnections()
	}
	if rt.http1trFallback != nil {
		rt.http1trFallback.CloseIdleConnections()
	}
}

// buildHTTP2Transport builds a new HTTP/2 transport using settings from builder.
func (rt *roundtripper) buildHTTP2Transport() *http2.Transport {
	t := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return rt.dialTLS(ctx, network, addr)
		},
		DisableCompression: rt.http1tr.DisableCompression,
		IdleConnTimeout:    rt.http1tr.IdleConnTimeout,
		PingTimeout:        _http2PingTimeout,
		ReadIdleTimeout:    _http2ReadIdleTimeout,
		WriteByteTimeout:   _http2WriteByteTimeout,
	}

	if rt.ja.builder.http2settings != nil {
		h := rt.ja.builder.http2settings

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

// dialTLS performs TLS handshake using uTLS.
func (rt *roundtripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	return rt.tlsHandshake(ctx, network, addr, false)
}

func (rt *roundtripper) dialTLSHTTP1(ctx context.Context, network, addr string) (net.Conn, error) {
	return rt.tlsHandshake(ctx, network, addr, true)
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

	config := &utls.Config{
		ServerName:             host,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		OmitEmptyPsk:           true,
		KeyLogWriter:           rt.ja.builder.cli.tlsConfig.KeyLogWriter,
	}

	if supportsResumption(spec) && rt.clientSessionCache != nil {
		config.ClientSessionCache = rt.clientSessionCache
		config.PreferSkipResumptionOnNilExtension = true
		config.SessionTicketsDisabled = false
	}

	uconn := utls.UClient(rawConn, config, utls.HelloCustom)
	if err = uconn.ApplyPreset(&spec); err != nil {
		uconn.Close()
		return nil, err
	}

	if err = uconn.HandshakeContext(ctx); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("uTLS.HandshakeContext() error: %+v", err)
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
		case *utls.SessionTicketExtension:
			hasSessionTicket = true
		case *utls.PSKKeyExchangeModesExtension:
			hasPskModes = true
		case *utls.UtlsPreSharedKeyExtension, *utls.FakePreSharedKeyExtension:
			hasPreSharedKey = true
		}

		// Early exit if all TLS 1.3 components are found
		if hasSessionTicket && hasPskModes && hasPreSharedKey {
			return true
		}
	}

	// If any TLS 1.3 PSK-related extensions are present,
	// session resumption is valid only when all required
	// TLS 1.3 resumption indicators are present simultaneously.
	if hasPskModes || hasPreSharedKey {
		return false
	}

	// Otherwise, fall back to TLS 1.2 semantics where the presence of
	// SessionTicketExtension alone indicates support for session resumption.
	return hasSessionTicket
}

// setAlpnProtocolToHTTP1 modifies the given ClientHelloSpec to prefer HTTP/1.1
// by updating or adding the ALPN extension.
func setAlpnProtocolToHTTP1(utlsSpec *utls.ClientHelloSpec) {
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
