package surf

import (
	"github.com/enetx/http"
)

// Preconnect warms the same JA transports used by RoundTrip. No alternate TLS
// implementation, request body reader or separate connection pool is introduced.
func (rt *roundtripper) Preconnect(req *http.Request) error {
	var err error
	req, err = rt.prepareProxy(req)
	if err != nil {
		return err
	}

	child, err := rt.proxyTransport(req)
	if err != nil {
		return err
	}

	if child != nil {
		return child.Preconnect(req)
	}

	if rt.http2tr != nil && req.URL.Scheme == "https" {
		return rt.http2tr.Preconnect(req)
	}

	return rt.http1tr.Preconnect(req)
}
