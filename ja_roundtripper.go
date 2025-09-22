package surf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/g/ref"
	"github.com/enetx/http"
	"github.com/enetx/http2"

	utls "github.com/enetx/utls"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundtripper struct {
	transport          http.RoundTripper
	clientSessionCache utls.ClientSessionCache
	ja                 *JA
	cachedConnections  *g.MapSafe[string, net.Conn]
	cachedTransports   *g.MapSafe[string, http.RoundTripper]
}

func newRoundTripper(ja *JA, transport http.RoundTripper) http.RoundTripper {
	rt := new(roundtripper)
	rt.ja = ja
	rt.transport = transport
	rt.cachedConnections = g.NewMapSafe[string, net.Conn]()
	rt.cachedTransports = g.NewMapSafe[string, http.RoundTripper]()

	if rt.ja.builder.session {
		rt.clientSessionCache = utls.NewLRUClientSessionCache(0)
	}

	return rt
}

func (rt *roundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := rt.address(req)

	transport := rt.cachedTransports.Get(addr)
	if transport.IsNone() {
		if err := rt.getTransport(req, addr); err != nil {
			return nil, err
		}

		transport = rt.cachedTransports.Get(addr)
	}

	response, err := transport.Some().RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (rt *roundtripper) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }

	for k, v := range rt.cachedTransports.Iter() {
		if tr, ok := v.(closeIdler); ok {
			tr.CloseIdleConnections()
		}

		rt.cachedTransports.Delete(k)
	}
}

func (rt *roundtripper) getTransport(req *http.Request, addr string) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		rt.cachedTransports.Set(addr, rt.buildHTTP1Transport())
		return nil
	case "https":
	default:
		return fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	_, err := rt.dialTLS(req.Context(), "tcp", addr)
	if errors.Is(err, errProtocolNegotiated) {
		return nil
	}

	return err
}

func (rt *roundtripper) dialTLSHTTP2(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	return rt.dialTLS(ctx, network, addr)
}

func (rt *roundtripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	if value := rt.cachedConnections.Get(addr); value.IsSome() {
		rt.cachedConnections.Delete(addr)
		return value.Some(), nil
	}

	rawConn, err := rt.transport.(*http.Transport).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	spec := rt.ja.getSpec()
	if spec.IsErr() {
		_ = rawConn.Close()
		return nil, spec.Err()
	}

	if rt.ja.builder.forseHTTP1 {
		setAlpnProtocolToHTTP1(ref.Of(spec.Ok()))
	}

	config := &utls.Config{
		ServerName:             host,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		OmitEmptyPsk:           true,
	}

	if supportsSession(spec.Ok()) && rt.clientSessionCache != nil {
		config.ClientSessionCache = rt.clientSessionCache
		config.PreferSkipResumptionOnNilExtension = true
		config.SessionTicketsDisabled = false
	}

	conn := utls.UClient(rawConn, config, utls.HelloCustom)
	if err = conn.ApplyPreset(ref.Of(spec.Ok())); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()

		if err.Error() == "tls: CurvePreferences includes unsupported curve" {
			return nil, fmt.Errorf("conn.HandshakeContext() error for tls 1.3 (please retry request): %+v", err)
		}

		return nil, fmt.Errorf("uTlsConn.HandshakeContext() error: %+v", err)
	}

	if value := rt.cachedTransports.Get(addr); value.IsSome() {
		return conn, nil
	}

	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		rt.cachedTransports.Set(addr, rt.buildHTTP2Transport())
	default:
		rt.cachedTransports.Set(addr, rt.buildHTTP1Transport())
	}

	rt.cachedConnections.Set(addr, conn)

	return nil, errProtocolNegotiated
}

func (rt *roundtripper) address(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}

	return net.JoinHostPort(req.URL.Host, "443") // we can assume port is 443 at this point
}

func (rt *roundtripper) buildHTTP1Transport() *http.Transport {
	t := rt.transport.(*http.Transport).Clone()
	t.DialTLSContext = rt.dialTLS

	return t
}

func (rt *roundtripper) buildHTTP2Transport() *http2.Transport {
	t := new(http2.Transport)
	t.DialTLSContext = rt.dialTLSHTTP2
	t.DisableCompression = rt.transport.(*http.Transport).DisableCompression
	t.IdleConnTimeout = rt.transport.(*http.Transport).IdleConnTimeout
	t.TLSClientConfig = rt.transport.(*http.Transport).TLSClientConfig

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

func supportsSession(spec utls.ClientHelloSpec) bool {
	hasSessionTicket := false
	hasPSK := false

	for _, ext := range spec.Extensions {
		switch ext.(type) {
		case *utls.SessionTicketExtension:
			hasSessionTicket = true
		case *utls.PSKKeyExchangeModesExtension:
			hasPSK = true
		case *utls.UtlsPreSharedKeyExtension:
			hasPSK = true
		}
	}

	// TLS 1.2 SessionTicket
	// TLS 1.3 PSK
	return hasSessionTicket || hasPSK
}

// setAlpnProtocolToHTTP1 updates the ALPN protocols of the provided ClientHelloSpec to include
// "http/1.1".
//
// It modifies the ALPN protocols of the first ALPNExtension found in the extensions of the
// provided spec.
// If no ALPNExtension is found, it does nothing.
//
// Note that this function modifies the provided spec in-place.
func setAlpnProtocolToHTTP1(utlsSpec *utls.ClientHelloSpec) {
	for _, Extension := range utlsSpec.Extensions {
		alpns, ok := Extension.(*utls.ALPNExtension)
		if ok {
			if i := slices.Index(alpns.AlpnProtocols, "h2"); i != -1 {
				alpns.AlpnProtocols = slices.Delete(alpns.AlpnProtocols, i, i+1)
			}

			if !slices.Contains(alpns.AlpnProtocols, "http/1.1") {
				alpns.AlpnProtocols = append([]string{"http/1.1"}, alpns.AlpnProtocols...)
			}

			break
		}
	}
}
