package surf

import (
	"context"
	"net/url"

	"github.com/enetx/http"
	"github.com/enetx/surf/pkg/connectproxy"
)

type (
	tlsProxyKey    struct{}
	proxySelection struct{ url *url.URL }
)

func withProxySelection(req *http.Request, proxy *url.URL) *http.Request {
	if proxy != nil {
		clone := *proxy
		proxy = &clone
	}

	return req.WithContext(context.WithValue(req.Context(), tlsProxyKey{}, proxySelection{url: proxy}))
}

// Plain HTTP forwarding remains with net/http. HTTPS tunnels are established
// before uTLS so net/http cannot substitute its native ClientHello.
func (rt *roundtripper) configureProxy() {
	if rt.requestProxy == nil {
		return
	}

	rt.http1tr.Proxy = func(req *http.Request) (*url.URL, error) {
		if req.URL.Scheme == "https" {
			return nil, nil
		}
		return rt.requestProxy(req)
	}
}

func (rt *roundtripper) prepareProxy(req *http.Request) (*http.Request, error) {
	if _, selected := req.Context().Value(tlsProxyKey{}).(proxySelection); selected {
		return req, nil
	}

	if rt.requestProxy == nil || req.URL.Scheme != "https" {
		return req, nil
	}

	proxy, err := rt.requestProxy(req)
	if err != nil {
		return req, err
	}

	return withProxySelection(req, proxy), nil
}

// Separate pools prevent a connection opened directly or through another
// proxy from being reused when an application proxy selector changes routes.
func (rt *roundtripper) proxyTransport(req *http.Request) (*roundtripper, error) {
	route, _ := req.Context().Value(tlsProxyKey{}).(proxySelection)
	if rt.requestProxy == nil || route.url == nil {
		return nil, nil
	}

	key := route.url.String()
	rt.proxyMu.Lock()
	if child := rt.proxyTransports[key]; child != nil {
		rt.proxyMu.Unlock()
		return child, nil
	}

	dialer, err := connectproxy.NewDialer(key)
	if err != nil {
		rt.proxyMu.Unlock()
		return nil, err
	}

	dialer.Dialer = *rt.ja.builder.cli.GetDialer()
	base := rt.http1tr.Clone()
	base.Proxy = nil
	base.DialContext = tcpBindingDial(dialer.DialContext)

	child := &roundtripper{
		http1tr:            base,
		ja:                 rt.ja,
		protocolHeaders:    rt.protocolHeaders,
		http2settings:      rt.http2settings,
		clientSessionCache: rt.clientSessionCache,
	}

	child.configureTransports(rt.http2tr != nil)
	if rt.proxyTransports == nil {
		rt.proxyTransports = make(map[string]*roundtripper)
	}

	var retired *roundtripper
	if len(rt.proxyTransports) >= 256 {
		for old, value := range rt.proxyTransports {
			retired = value
			delete(rt.proxyTransports, old)

			break
		}
	}

	rt.proxyTransports[key] = child
	rt.proxyMu.Unlock()

	if retired != nil {
		retired.CloseIdleConnections()
	}

	return child, nil
}

func (rt *roundtripper) closeProxyIdleConnections() {
	rt.proxyMu.Lock()
	children := make([]*roundtripper, 0, len(rt.proxyTransports))
	for _, child := range rt.proxyTransports {
		children = append(children, child)
	}
	rt.proxyMu.Unlock()

	for _, child := range children {
		child.CloseIdleConnections()
	}
}
