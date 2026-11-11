package h3transport

import (
	"context"
	"net/url"

	"github.com/enetx/http"
)

// A TCP proxy bypasses local discovery, but a previously authenticated ECH
// binding must survive a routing change. An expired binding fails closed.
func (ut *Transport) roundTripProxy(req *http.Request) (*http.Response, error) {
	if ut.discovery != nil && req.URL.Scheme == "https" {
		origin, err := raceAddress(req)
		if err == nil && ut.discovery.expiredECH(origin) {
			err = errHTTPSBindingExpired
		}

		if err == nil {
			if binding, ok := ut.discovery.binding(origin); ok {
				if !binding.tcp {
					err = errHTTPSNoTCP
				} else {
					route := binding.alternativeRoute
					route.tcpAddress = binding.address
					req = req.WithContext(context.WithValue(req.Context(), alternativeRouteKey{}, route))
				}
			}
		}

		if err != nil {
			if req.Body != nil {
				req.Body.Close()
			}

			return nil, err
		}
	}

	return ut.Fallback.RoundTrip(req)
}

type (
	tlsProxyKey    struct{}
	proxySelection struct{ url *url.URL }
)

func WithProxySelection(req *http.Request, proxy *url.URL) *http.Request {
	if proxy != nil {
		clone := *proxy
		proxy = &clone
	}

	return req.WithContext(context.WithValue(req.Context(), tlsProxyKey{}, proxySelection{url: proxy}))
}

func SelectedProxy(req *http.Request) (*url.URL, bool) {
	selected, ok := req.Context().Value(tlsProxyKey{}).(proxySelection)
	return selected.url, ok
}
