package surf

import (
	"container/list"
	"net/url"
	"sync"

	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/surf/internal/origin"
)

// http1RequiredCache is client-local server state, shared by its proxy routes.
// Reads refresh LRU order; closing idle sockets does not clear requirements.
// Chromium neither expires these entries by time nor persists them to disk.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_server_properties.h
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_server_properties.cc
type http1RequiredCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]*list.Element
	lru      list.List
}

func (s *http1RequiredCache) contains(key string) bool {
	if s == nil || key == "" {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if e := s.entries[key]; e != nil {
		s.lru.MoveToFront(e)
		return true
	}

	return false
}

func (s *http1RequiredCache) remember(key string) {
	if s == nil || s.capacity <= 0 || key == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if e := s.entries[key]; e != nil {
		s.lru.MoveToFront(e)
		return
	}

	if s.entries == nil {
		s.entries = make(map[string]*list.Element)
	}

	if len(s.entries) == s.capacity {
		e := s.lru.Back()
		delete(s.entries, e.Value.(string))
		s.lru.Remove(e)
	}

	s.entries[key] = s.lru.PushFront(key)
}

func (rt *roundtripper) requiresHTTP1(req *http.Request) bool {
	if rt.http1Required == nil {
		return false
	}

	key, _ := origin.Key(req.URL)

	return rt.http1Required.contains(key)
}

func tlsOrigin(address string) string {
	key, _ := origin.Key(&url.URL{Scheme: "https", Host: address})
	return key
}

// Chromium promotes HTTP_1_1_REQUIRED from an active RST_STREAM or GOAWAY
// to session shutdown. Publish origin state before the engine wakes requests.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/spdy/spdy_session.cc
func (rt *roundtripper) connectionErrorPolicy(info http2.ConnectionErrorInfo) bool {
	if info.Code != http2.ErrCodeHTTP11Required {
		return false
	}

	conn, ok := info.Conn.(*profileTLSConn)
	if !ok || conn.origin == "" {
		return false
	}

	rt.http1Required.remember(conn.origin)

	return true
}
