package surf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/enetx/g"
	"github.com/enetx/g/cell"
	"github.com/enetx/g/ref"
	"github.com/enetx/http"
	"github.com/enetx/http2"

	utls "github.com/enetx/utls"
)

type roundtripper struct {
	transport          *http.Transport
	clientSessionCache utls.ClientSessionCache
	ja                 *JA
	cachedTransports   *g.MapSafe[string, *cell.LazyCell[g.Result[http.RoundTripper]]]
}

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

func (rt *roundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := rt.address(req)
	scheme := g.String(req.URL.Scheme).Lower()
	entry := rt.cachedTransports.Entry(addr)

	cellOpt := entry.OrSetBy(func() *cell.LazyCell[g.Result[http.RoundTripper]] {
		ctx := req.Context()

		return cell.NewLazy(func() g.Result[http.RoundTripper] {
			var (
				tr  http.RoundTripper
				err error
			)

			switch scheme {
			case "http":
				tr = rt.buildHTTP1Transport()
			case "https":
				tr, err = rt.buildHTTPSTransport(ctx, addr)
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

func (rt *roundtripper) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }

	for addr, lazy := range rt.cachedTransports.Iter() {
		if transport := lazy.Force(); transport.IsOk() {
			if ci, ok := transport.Ok().(closeIdler); ok {
				ci.CloseIdleConnections()
			}
		}

		rt.cachedTransports.Delete(addr)
	}
}

func (rt *roundtripper) buildHTTPSTransport(ctx context.Context, addr string) (http.RoundTripper, error) {
	negProto, err := rt.probeALPN(ctx, addr)
	if err != nil {
		return nil, err
	}

	switch negProto {
	case http2.NextProtoTLS:
		return rt.buildHTTP2Transport(), nil
	default:
		return rt.buildHTTP1Transport(), nil
	}
}

func (rt *roundtripper) probeALPN(ctx context.Context, addr string) (string, error) {
	conn, err := rt.tlsHandshake(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}

	defer conn.Close()

	return conn.ConnectionState().NegotiatedProtocol, nil
}

func (rt *roundtripper) dialTLSHTTP2(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	return rt.dialTLS(ctx, network, addr)
}

func (rt *roundtripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	return rt.tlsHandshake(ctx, network, addr)
}

func (rt *roundtripper) tlsHandshake(ctx context.Context, network, addr string) (*utls.UConn, error) {
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
		_ = rawConn.Close()
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
	}

	if rt.ja != nil && rt.ja.builder != nil && rt.ja.builder.cli != nil {
		if baseTLS := rt.ja.builder.cli.tlsConfig; baseTLS != nil && baseTLS.KeyLogWriter != nil {
			config.KeyLogWriter = baseTLS.KeyLogWriter
		}
	}

	if supportsResumption(spec.Ok()) && rt.clientSessionCache != nil {
		config.ClientSessionCache = rt.clientSessionCache
		config.PreferSkipResumptionOnNilExtension = true
		config.SessionTicketsDisabled = false
	}

	uconn := utls.UClient(rawConn, config, utls.HelloCustom)
	if err = uconn.ApplyPreset(ref.Of(spec.Ok())); err != nil {
		_ = uconn.Close()
		return nil, err
	}

	if err = uconn.HandshakeContext(ctx); err != nil {
		_ = uconn.Close()

		if strings.Contains(err.Error(), "CurvePreferences includes unsupported curve") {
			return nil, fmt.Errorf("conn.HandshakeContext() error for tls 1.3 (please retry request): %+v", err)
		}

		return nil, fmt.Errorf("uTlsConn.HandshakeContext() error: %+v", err)
	}

	return uconn, nil
}

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

func (rt *roundtripper) buildHTTP1Transport() *http.Transport {
	t := rt.transport.Clone()
	t.DialTLSContext = rt.dialTLS

	return t
}

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

// setAlpnProtocolToHTTP1 updates the ALPN protocols of the provided ClientHelloSpec to include
// "http/1.1".
//
// It modifies the ALPN protocols of the first ALPNExtension found in the extensions of the
// provided spec.
// If no ALPNExtension is found, it does nothing.
//
// Note that this function modifies the provided spec in-place.
func setAlpnProtocolToHTTP1(utlsSpec *utls.ClientHelloSpec) {
	for _, ext := range utlsSpec.Extensions {
		alpns, ok := ext.(*utls.ALPNExtension)
		if !ok {
			continue
		}

		if i := slices.Index(alpns.AlpnProtocols, "h2"); i != -1 {
			alpns.AlpnProtocols = slices.Delete(alpns.AlpnProtocols, i, i+1)
		}

		if !slices.Contains(alpns.AlpnProtocols, "http/1.1") {
			alpns.AlpnProtocols = append(alpns.AlpnProtocols, "http/1.1")
		}

		break
	}
}
