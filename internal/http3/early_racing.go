package h3transport

import (
	"context"
	"io"

	"github.com/enetx/http"
)

// Firefox leaves its TCP backup timer active while a transaction uses 0-RTT.
// A ready backup may restart that transaction until QUIC is connected.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http3Session.cpp#L1491
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp#L3935
// This path is restricted to the same bodyless GET/HEAD eligible for early data.
func (ut *Transport) roundTripEarlyBackup(req *http.Request, address string) (*http.Response, error) {
	ctx, cancel := context.WithCancel(req.Context())
	decision := make(chan bool, 1)
	type result struct {
		response *http.Response
		err      error
	}
	completed := make(chan result)
	go func() {
		var selected, decided bool
		choose := func() bool {
			if !decided {
				select {
				case selected = <-decision:
				case <-ctx.Done():
				}
				decided = true
			}
			return selected && ctx.Err() == nil
		}
		conn, err := ut.http3tr.PreconnectEarly(ctx, address)
		var response *http.Response
		if err == nil {
			select {
			case <-conn.HandshakeComplete():
				// A cold or already confirmed connection sends only after it wins.
				if !choose() {
					return
				}
			default:
			}
			if ctx.Err() == nil {
				response, err = ut.roundTripHTTP3(req.WithContext(ctx))
			} else {
				err = context.Cause(ctx)
			}
		}
		if choose() {
			select {
			case completed <- result{response, err}:
				return
			case <-ctx.Done():
			}
		}
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
	}()

	selection, err := ut.racer.SelectProtocol(req, address, false)
	if err != nil {
		cancel()
		return nil, err
	}
	useQUIC := selection.Protocol == 3 || !requestProgress(req).allowFallback()
	decision <- useQUIC
	if !useQUIC {
		cancel()
		if selection.HTTP1 {
			req = req.WithContext(context.WithValue(req.Context(), preparedTCPHTTP1Key{}, true))
		}
		return ut.Fallback.RoundTrip(req)
	}
	select {
	case r := <-completed:
		if r.err != nil || r.response == nil || r.response.Body == nil {
			cancel()
		} else {
			r.response.Body = &earlyRacingBody{ReadCloser: r.response.Body, cancel: cancel}
		}
		return r.response, r.err
	case <-ctx.Done():
		cancel()
		return nil, context.Cause(ctx)
	}
}

type earlyRacingBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *earlyRacingBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
