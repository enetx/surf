package h3transport

import (
	"context"

	"github.com/enetx/http"
)

// Chromium's 421 retry is transaction-local: disable IP pooling and alternative
// services for this retry, without poisoning the original shared connection.
// Streaming bodies without a reproducible source are not replayed.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_network_transaction.cc
func (ut *Transport) finishHTTP3Attempt(req *http.Request, response *http.Response, err error) (*http.Response, error) {
	if err != nil || response.StatusCode != http.StatusMisdirectedRequest ||
		ut.coalescer == nil || !ut.coalescer.enabled || req.Context().Err() != nil {
		return response, err
	}

	if retried, _ := req.Context().Value(coalescingRetryKey{}).(bool); retried {
		return response, nil
	}

	if !ut.forceHTTP3 && ut.Fallback == nil {
		return response, nil
	}

	retry := *req
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return response, nil
		}

		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return response, nil
		}

		retry.Body = body
	}

	response.Body.Close()
	ctx := context.WithValue(req.Context(), coalescingRetryKey{}, true)

	// Alt-Svc cannot redirect this retry. Preserve independently authenticated
	// HTTPS-record/ECH policy, including no-default-alpn and service targets.
	route := alternativeRoute{}
	if ut.discovery != nil {
		origin, addressErr := raceAddress(req)
		if addressErr != nil {
			closeRequestBody(&retry)
			return nil, addressErr
		}

		resolved, _ := ut.discovery.resolve(ctx, origin)
		if ut.discovery.expiredECH(origin) {
			closeRequestBody(&retry)
			return nil, errHTTPSBindingExpired
		}

		if binding, ok := ut.discovery.binding(origin); ok {
			route = binding.alternativeRoute
			route.tcpAddress = binding.address
			route.noTCP = !binding.tcp
		}

		route.resolved = resolved.resolved
	}

	retry = *retry.WithContext(context.WithValue(ctx, alternativeRouteKey{}, route))
	if ut.forceHTTP3 {
		return ut.roundTripHTTP3(&retry)
	}

	if route.noTCP {
		closeRequestBody(&retry)
		return nil, errHTTPSNoTCP
	}

	return ut.Fallback.RoundTrip(&retry)
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}
