package quictls

import (
	"crypto/tls"

	utls "github.com/enetx/utls"
)

// Session caches have public serialization APIs. The ticket is carried separately
// from SessionState.Bytes, which intentionally does not serialize the ticket.
// Encoding changes across Go/uTLS versions result in a cache miss, never an
// unchecked cast of private structures. Live session events don't serialize.
type sessionCache struct{ cache tls.ClientSessionCache }

// TCPSessionCache preserves application cache ownership while keeping TCP TLS
// tickets independent of QUIC's transport-specific cached state.
func TCPSessionCache(cache tls.ClientSessionCache) utls.ClientSessionCache {
	return sessionCache{cache: TCPCache(cache)}
}

// TCPCache separates ordinary TLS keys from QUIC, including native Go TLS.
func TCPCache(cache tls.ClientSessionCache) tls.ClientSessionCache {
	if cache == nil {
		return nil
	}

	if _, wrapped := cache.(tcpSessionCache); wrapped {
		return cache
	}

	return tcpSessionCache{cache}
}

// BaseTCPCache recovers the application cache from Surf's own key namespace.
// Arbitrary application wrappers retain their identity and behavior.
func BaseTCPCache(cache tls.ClientSessionCache) tls.ClientSessionCache {
	if wrapped, ok := cache.(tcpSessionCache); ok {
		return wrapped.ClientSessionCache
	}

	return cache
}

type tcpSessionCache struct{ tls.ClientSessionCache }

func (c tcpSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	return c.ClientSessionCache.Get("tcp:" + key)
}

func (c tcpSessionCache) Put(key string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put("tcp:"+key, state)
}

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
