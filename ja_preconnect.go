package surf

import (
	"github.com/enetx/http"
	h3transport "github.com/enetx/surf/internal/http3"
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

	if req.URL.Scheme != "https" || rt.http2tr == nil {
		return rt.http1tr.Preconnect(req)
	}

	err = rt.http2tr.Preconnect(req)
	if err == nil || !wantsHTTP1(err) || req.Context().Err() != nil {
		return err
	}

	if err := rt.http1trFallback.Preconnect(req); err != nil {
		return err
	}

	h3transport.MarkPreparedHTTP1(req.Context())

	return nil
}
