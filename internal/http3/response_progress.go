package h3transport

import (
	"context"
	"sync/atomic"

	"github.com/enetx/http"
	"github.com/enetx/quic-go/http3"
)

type responseProgressKey struct{}

// Receiving a valid response commits the transaction to QUIC, including 1xx.
// A concurrent TCP backup must commit first or leave this response alone.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_network_transaction.cc
type responseProgress struct{ state atomic.Uint32 }

const (
	responsePending uint32 = iota
	responseReceived
	responseFallback
)

func (p *responseProgress) observe() bool {
	return p == nil || p.state.CompareAndSwap(responsePending, responseReceived) || p.state.Load() == responseReceived
}

func (p *responseProgress) allowFallback() bool {
	return p == nil || p.state.CompareAndSwap(responsePending, responseFallback) || p.state.Load() == responseFallback
}

func requestProgress(req *http.Request) *responseProgress {
	p, _ := req.Context().Value(responseProgressKey{}).(*responseProgress)
	return p
}

func responseWireConfig(config *http3.WireConfig) *http3.WireConfig {
	config = config.Clone()
	if config == nil {
		config = &http3.WireConfig{}
	}
	callback := config.OnResponseHeaders
	config.OnResponseHeaders = func(req *http.Request, response *http.Response) error {
		if !requestProgress(req).observe() {
			return context.Canceled
		}
		if callback != nil {
			return callback(req, response)
		}
		return nil
	}
	return config
}
