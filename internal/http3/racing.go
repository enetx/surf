package h3transport

import (
	"context"
	"errors"

	"github.com/enetx/http"
	"github.com/enetx/surf/internal/connrace"
)

type Preconnector interface{ Preconnect(*http.Request) error }

type preparedTCPHTTP1Key struct{}

func raceAddress(req *http.Request) (string, error) {
	return connrace.Address(req)
}

func (ut *Transport) roundTripRacing(req *http.Request) (*http.Response, error) {
	address, err := raceAddress(req)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}

	selection, err := ut.racer.SelectProtocol(req, address)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	// After selection, only the selected normal transport owns the body. Never
	// retry a failed application exchange against the other protocol here.
	if selection.Protocol == 3 {
		return ut.roundTripHTTP3(req)
	}

	if selection.HTTP1 {
		req = req.WithContext(context.WithValue(req.Context(), preparedTCPHTTP1Key{}, true))
	}

	return ut.Fallback.RoundTrip(req)
}

func (ut *Transport) preconnectTCP(req *http.Request) error {
	// JA wraps the fallback after the HTTP/3 factory runs. Resolve the current
	// transport at use time, so preparation and sending always use the same TLS.
	preconnect, ok := ut.Fallback.(Preconnector)
	if !ok {
		return errors.New("surf: TCP transport does not support Preconnect")
	}

	return preconnect.Preconnect(req)
}
func PreparedHTTP1(ctx context.Context) bool {
	preferred, _ := ctx.Value(preparedTCPHTTP1Key{}).(bool)
	return preferred
}

func MarkPreparedHTTP1(ctx context.Context) {
	if preferred, ok := ctx.Value(preparedTCPHTTP1Key{}).(*bool); ok {
		*preferred = true
	}
}
