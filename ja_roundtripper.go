package surf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/g/ref"
	"github.com/enetx/http"
	"github.com/enetx/http2"

	utls "github.com/enetx/utls"
)

// roundtripper is a higher-level wrapper around HTTP transports, providing
// TLS session resumption and protocol selection.
type roundtripper struct {
	http1tr            *http.Transport
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

	if !ja.builder.forceHTTP1 {
		rt.http2tr = rt.buildHTTP2Transport()
	}

	return rt
}

// RoundTrip executes a single HTTP request.
// Optimized for parsing different sites (no per-request allocations).
func (rt *roundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	scheme := g.String(req.URL.Scheme).Lower()

	switch scheme {
	case "http":
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
	if ctxErr := req.Context().Err(); ctxErr != nil {
		return nil, ctxErr
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
	return rt.http1tr.RoundTrip(req)
}

// CloseIdleConnections closes all idle connections.
func (rt *roundtripper) CloseIdleConnections() {
	if rt.http1tr != nil {
		rt.http1tr.CloseIdleConnections()
	}

	if rt.http2tr != nil {
		rt.http2tr.CloseIdleConnections()
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
		ReadIdleTimeout:    _http2ReadIdleTimeout,
		PingTimeout:        _http2PingTimeout,
		WriteByteTimeout:   _http2WriteByteTimeout,
	}

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

// dialTLS performs TLS handshake using uTLS.
func (rt *roundtripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	return rt.tlsHandshake(ctx, network, addr)
}

// tlsHandshake performs a full TLS handshake using uTLS, applying JA fingerprint
// presets and optionally enabling session resumption.
func (rt *roundtripper) tlsHandshake(ctx context.Context, network, addr string) (*utls.UConn, error) {
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

	spec := rt.ja.getSpec()
	if spec.IsErr() {
		rawConn.Close()
		return nil, spec.Err()
	}

	// Apply HTTP/1 ALPN if forced
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
		if alpns, ok := ext.(*utls.ALPNExtension); ok {
			// Remove h2 and ensure http/1.1 is present
			protocols := make([]string, 0, len(alpns.AlpnProtocols))
			hasHTTP1 := false

			for _, proto := range alpns.AlpnProtocols {
				if proto == "h2" {
					continue
				}

				if proto == "http/1.1" {
					hasHTTP1 = true
				}

				protocols = append(protocols, proto)
			}

			if !hasHTTP1 {
				protocols = append(protocols, "http/1.1")
			}

			alpns.AlpnProtocols = protocols
			return
		}
	}

	// Add new ALPN extension if not present
	utlsSpec.Extensions = append(utlsSpec.Extensions, &utls.ALPNExtension{
		AlpnProtocols: []string{"http/1.1"},
	})
}
