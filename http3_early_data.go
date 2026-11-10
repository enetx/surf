package surf

import (
	"context"
	"errors"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
)

// EarlyData opts bodyless GET and HEAD requests into TLS 0-RTT on resumed
// HTTP/3 connections. Disabled by default. Enable only when replay of these
// requests is acceptable; POST and requests with bodies always wait for 1-RTT.
// A TLS ClientSessionCache is needed to resume a connection. Custom uTLS
// ClientHello templates currently do not support this option.
func (h *HTTP3Settings) EarlyData(enabled bool) *HTTP3Settings {
	h.earlyData = enabled
	return h
}

type http3RequireHandshakeKey struct{}

func (ut *uquicTransport) roundTripHTTP3(req *http.Request) (*http.Response, error) {
	attempt := ut.requestWithAltUsed(withProtocolHeaders(req, ut.protocolHeaders, 3))

	eligible := ut.earlyData && (req.Body == nil || req.Body == http.NoBody) &&
		(req.Method == http.MethodGet || req.Method == http.MethodHead)
	if !eligible {
		if ut.earlyData {
			attempt = attempt.WithContext(context.WithValue(attempt.Context(), http3RequireHandshakeKey{}, true))
		}

		return ut.http3tr.RoundTrip(attempt)
	}

	clone := *attempt

	if req.Method == http.MethodGet {
		clone.Method = http3.MethodGet0RTT
	} else {
		clone.Method = http3.MethodHead0RTT
	}

	response, err := ut.http3tr.RoundTrip(&clone)
	if !errors.Is(err, quic.Err0RTTRejected) && (err != nil || response.StatusCode != http.StatusTooEarly) {
		return response, err
	}

	if response != nil {
		response.Body.Close()
	}

	// Retry at most once, after the handshake. Retain the original method and
	// request context; a new dial must not attempt early data either.
	retry := attempt.WithContext(context.WithValue(attempt.Context(), http3RequireHandshakeKey{}, true))

	return ut.http3tr.RoundTrip(retry)
}

func (ut *uquicTransport) useEarlyData(ctx context.Context) bool {
	required, _ := ctx.Value(http3RequireHandshakeKey{}).(bool)
	return ut.earlyData && !required
}
