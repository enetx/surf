package surf

import "github.com/enetx/http"

// Preconnect warms the same JA transports used by RoundTrip. No alternate TLS
// implementation, request body reader or separate connection pool is introduced.
func (rt *roundtripper) Preconnect(req *http.Request) error {
	if req.URL.Scheme != "https" || rt.http2tr == nil {
		return rt.http1tr.Preconnect(req)
	}
	err := rt.http2tr.Preconnect(req)
	if err == nil || !wantsHTTP1(err) || req.Context().Err() != nil {
		return err
	}
	if err := rt.http1trFallback.Preconnect(req); err != nil {
		return err
	}
	if preferred, ok := req.Context().Value(preparedTCPHTTP1Key{}).(*bool); ok {
		*preferred = true
	}
	return nil
}
