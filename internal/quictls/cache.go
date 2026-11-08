package quictls

import (
	"crypto/tls"

	utls "github.com/refraction-networking/utls"
)

// Session caches have public serialization APIs. The ticket is carried separately
// from SessionState.Bytes, which intentionally does not serialize the ticket.
// Encoding changes across Go/uTLS versions result in a cache miss, never an
// unchecked cast of private structures. Live session events don't serialize.
type sessionCache struct{ cache tls.ClientSessionCache }

func (c sessionCache) Get(key string) (*utls.ClientSessionState, bool) {
	state, ok := c.cache.Get(key)
	if !ok || state == nil {
		return nil, false
	}

	ticket, s, err := state.ResumptionState()
	if err != nil {
		return nil, false
	}

	data, err := s.Bytes()
	if err != nil {
		return nil, false
	}

	converted, err := utls.ParseSessionState(data)
	if err != nil {
		return nil, false
	}

	result, err := utls.NewResumptionState(ticket, converted)

	return result, err == nil
}

func (c sessionCache) Put(key string, state *utls.ClientSessionState) {
	if state == nil {
		c.cache.Put(key, nil)
		return
	}

	ticket, s, err := state.ResumptionState()
	if err != nil {
		return
	}

	data, err := s.Bytes()
	if err != nil {
		return
	}

	converted, err := tls.ParseSessionState(data)
	if err != nil {
		return
	}

	result, err := tls.NewResumptionState(ticket, converted)
	if err != nil {
		return
	}

	c.cache.Put(key, result)
}
