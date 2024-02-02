package surf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/http2"
	"gitlab.com/x0xO/surf/internal/ja3c"

	utls "github.com/refraction-networking/utls"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundtripper struct {
	transport          http.RoundTripper
	clientSessionCache utls.ClientSessionCache
	ja3                *ja3
	cachedConnections  sync.Map
	cachedTransports   sync.Map
}

func newRoundTripper(ja3 *ja3, transport http.RoundTripper) http.RoundTripper {
	rt := new(roundtripper)
	rt.ja3 = ja3
	rt.transport = transport

	if rt.ja3.opt.session {
		// rt.clientSessionCache = utls.NewLRUClientSessionCache(0)
	}

	return rt
}

func (rt *roundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := rt.address(req)

	value, ok := rt.cachedTransports.Load(addr)
	if !ok {
		if err := rt.getTransport(req, addr); err != nil {
			return nil, err
		}

		value, _ = rt.cachedTransports.Load(addr)
	}

	transport, ok := value.(http.RoundTripper)
	if !ok {
		return nil, fmt.Errorf("cached value is not of type http.RoundTripper for address: %s", addr)
	}

	response, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (rt *roundtripper) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }

	rt.cachedTransports.Range(func(key, transport any) bool {
		if tr, ok := transport.(closeIdler); ok {
			tr.CloseIdleConnections()
		}

		rt.cachedTransports.Delete(key)
		return true
	})
}

func (rt *roundtripper) getTransport(req *http.Request, addr string) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		rt.cachedTransports.Store(addr, rt.buildHTTP1Transport())
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
	// If we have the connection from when we determined the HTTPS
	// cachedTransports to use, return that.
	if value, ok := rt.cachedConnections.LoadAndDelete(addr); ok {
		return value.(net.Conn), nil
	}

	rawConn, err := rt.transport.(*http.Transport).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	spec, err := rt.ja3.getSpec()
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	// spec = ja3c.ProcessSpec(spec)

	if rt.ja3.opt.forseHTTP1 {
		ja3c.SetAlpnProtocolToHTTP1(&spec)
	}

	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		OmitEmptyPsk:       true,
		ClientSessionCache: rt.clientSessionCache,
	}

	conn := utls.UClient(rawConn, config, utls.HelloCustom)

	if err = conn.ApplyPreset(&spec); err != nil {
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

	if _, ok := rt.cachedTransports.Load(addr); ok {
		return conn, nil
	}

	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		rt.cachedTransports.Store(addr, rt.buildHTTP2Transport())
	default:
		rt.cachedTransports.Store(addr, rt.buildHTTP1Transport())
	}

	rt.cachedConnections.Store(addr, conn)

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

	if rt.ja3.opt.http2s != nil {
		h := rt.ja3.opt.http2s

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
