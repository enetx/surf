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

	utls "github.com/refraction-networking/utls"
)

var (
	errProtocolNegotiated = errors.New("protocol negotiated")
	cachedTransports      sync.Map
)

type roundtripper struct {
	dialContext       func(ctx context.Context, network, address string) (net.Conn, error)
	ja3               *ja3
	cachedConnections sync.Map
}

func newRoundtripper(ja3 *ja3, dialContext func(context.Context, string, string) (net.Conn, error)) http.RoundTripper {
	rt := new(roundtripper)
	rt.dialContext = dialContext
	rt.ja3 = ja3

	return rt
}

func (rt *roundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := rt.getDialTLSAddr(req)

	value, ok := cachedTransports.Load(addr)

	if !ok {
		if err := rt.getTransport(req, addr); err != nil {
			return nil, err
		}

		value, _ = cachedTransports.Load(addr)
	}

	response, err := value.(http.RoundTripper).RoundTrip(req)
	if err != nil {
		cachedTransports.Delete(addr)

		return nil, err
	}

	return response, err
}

func (rt *roundtripper) getTransport(req *http.Request, addr string) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		cachedTransports.Store(addr, &http.Transport{DialContext: rt.dialContext, DisableKeepAlives: true})
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

func (rt *roundtripper) dialTLSHTTP2(network, addr string, _ *tls.Config) (net.Conn, error) {
	return rt.dialTLS(context.Background(), network, addr)
}

func (rt *roundtripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	// If we have the connection from when we determined the HTTPS
	// cachedTransports to use, return that.
	if value, ok := rt.cachedConnections.LoadAndDelete(addr); ok {
		return value.(net.Conn), nil
	}

	rawConn, err := rt.dialContext(ctx, network, addr)
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

	spec = processSpec(spec)

	if rt.ja3.opt.forseHTTP1 {
		setAlpnProtocolToHTTP1(&spec)
	}

	config := &utls.Config{
		ServerName:         host,
		OmitEmptyPsk:       true,
		InsecureSkipVerify: true,
	}

	conn := utls.UClient(rawConn, config, utls.HelloCustom)

	if err = conn.ApplyPreset(&spec); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err = conn.Handshake(); err != nil {
		_ = conn.Close()

		if err.Error() == "tls: CurvePreferences includes unsupported curve" {
			return nil, fmt.Errorf("conn.Handshake() error for tls 1.3 (please retry request): %+v", err)
		}

		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	if _, ok := cachedTransports.Load(addr); ok {
		return conn, nil
	}

	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		t2 := http2.Transport{DialTLS: rt.dialTLSHTTP2}

		if rt.ja3.opt.useHTTP2s {
			t2.Settings = []http2.Setting{}

			h := rt.ja3.opt.http2s

			if h.headerTableSize != 0 {
				t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingHeaderTableSize, Val: h.headerTableSize})
			}

			if h.usePush {
				t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingEnablePush, Val: h.enablePush})
			}

			if h.maxConcurrentStreams != 0 {
				t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: h.maxConcurrentStreams})
			}

			if h.initialWindowSize != 0 {
				t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingInitialWindowSize, Val: h.initialWindowSize})
			}

			if h.maxFrameSize != 0 {
				t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingMaxFrameSize, Val: h.maxFrameSize})
			}

			if h.maxHeaderListSize != 0 {
				t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: h.maxHeaderListSize})
			}

			if !h.priorityParam.IsZero() {
				t2.PriorityParam = h.priorityParam
			}

			if h.priorityFrames != nil {
				t2.PriorityFrames = h.priorityFrames
			}
		}

		cachedTransports.Store(addr, &t2)
	default:
		cachedTransports.Store(addr, &http.Transport{DialTLSContext: rt.dialTLS, DisableKeepAlives: true})
	}

	rt.cachedConnections.Store(addr, conn)

	return nil, errProtocolNegotiated
}

func (rt *roundtripper) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}

	return net.JoinHostPort(req.URL.Host, "443") // we can assume port is 443 at this point
}
