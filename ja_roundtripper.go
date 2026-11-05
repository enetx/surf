package surf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http2"

	utls "github.com/refraction-networking/utls"
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

	if connClosedBeforeResponse(err) {
		// The server closed an established HTTP/2 connection before it answered this request.
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

// h2DialError marks a failure to open the HTTP/2 connection, so that it is never mistaken for
// a connection the server closed after the handshake. A proxy tunnel can fail its own
// handshake with io.ErrUnexpectedEOF too.
type h2DialError struct{ err error }

func (e *h2DialError) Error() string { return e.err.Error() }
func (e *h2DialError) Unwrap() error { return e.err }

// connClosedBeforeResponse reports whether an established HTTP/2 connection was closed or reset
// by the server before the response headers arrived. RoundTrip returns no error once the
// headers are in, so every such error means the request got no answer.
func connClosedBeforeResponse(err error) bool {
	var de *h2DialError
	if errors.As(err, &de) {
		return false
	}

	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
}

// errALPNNotH2 is returned by dialTLSHTTP2 when the server's ALPN choice was not h2.
var errALPNNotH2 = errors.New("surf: server did not negotiate h2")

// wantsHTTP1 reports whether the server asked for HTTP/1.1, the only HTTP/2 failures after
// which Chrome sends the request again over HTTP/1.1:
//   - the server picked http/1.1 (or no protocol) in ALPN. Chrome then simply speaks
//     HTTP/1.1 on that connection; surf's HTTP/2 transport cannot, so it redials;
//   - the server reset the stream, or sent GOAWAY, with HTTP_1_1_REQUIRED.
//
// Every other failure is returned as it is, as Chrome does. A connect or TLS handshake
// timeout, a refused or reset connection, or a TLS alert would only be repeated against the
// same address: a residential exit that accepts the connection but never relays the
// handshake made every such request wait out the handshake timeout twice. A stream reset by
// the server is its answer to the request: Akamai Bot Manager resets a request carrying a
// stale ak_bmsc over HTTP/2 and holds the same request over HTTP/1.1 with no response.
func wantsHTTP1(err error) bool {
	if errors.Is(err, errALPNNotH2) {
		return true
	}

	var se http2.StreamError
	if errors.As(err, &se) {
		return se.Code == http2.ErrCodeHTTP11Required
	}

	var ga http2.GoAwayError
	if errors.As(err, &ga) {
		return ga.ErrCode == http2.ErrCodeHTTP11Required
	}

	// http2 v1.0.26 returns an untyped error when GOAWAY rejects stream 1
	// with LastStreamID=0. Match its complete message until that path also
	// returns a GoAwayError; other GOAWAY codes must not enable fallback.
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

// buildHTTP2Transport builds a new HTTP/2 transport using settings from builder.
func (rt *roundtripper) buildHTTP2Transport() *http2.Transport {
	t := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return rt.dialTLSHTTP2(ctx, network, addr)
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

// dialTLS performs TLS handshake using uTLS with default ALPN (h2, http/1.1).
func (rt *roundtripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	return rt.tlsHandshake(ctx, network, addr, false)
}

// dialTLSHTTP2 performs TLS handshake and ensures ALPN selected HTTP/2.
// If ALPN negotiated HTTP/1.1 (or no protocol), this fails before any HTTP/2 bytes are written.
func (rt *roundtripper) dialTLSHTTP2(ctx context.Context, network, addr string) (net.Conn, error) {
	uconn, err := rt.tlsHandshake(ctx, network, addr, false)
	if err != nil {
		return nil, &h2DialError{err}
	}

	negotiatedProtocol := uconn.ConnectionState().NegotiatedProtocol
	if negotiatedProtocol != "h2" {
		uconn.Close()
		return nil, fmt.Errorf("%w: negotiated ALPN %q, expected h2", errALPNNotH2, negotiatedProtocol)
	}

	return uconn, nil
}

// dialTLSHTTP1 performs TLS handshake using uTLS with HTTP/1.1 only ALPN.
// Used for fallback when HTTP/2 connection fails.
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
		InsecureSkipVerify:     rt.ja.builder.cli.tlsConfig.InsecureSkipVerify,
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
