package surf

import (
	"container/list"
	"net/url"
	"sync"
	"time"

	"github.com/enetx/surf/internal/origin"
)

type clientHintStore struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	lru      list.List
	capacity int
	lifetime time.Duration
	clock    func() time.Time
}
type clientHintEntry struct {
	origin  string
	hints   []string
	expires time.Time
}

func newClientHintStore(capacity int, lifetime time.Duration, clock func() time.Time) *clientHintStore {
	return &clientHintStore{
		entries:  make(map[string]*list.Element),
		capacity: capacity,
		lifetime: lifetime,
		clock:    clock,
	}
}

func (s *clientHintStore) get(origin string) []string {
	now := s.clock()

	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.entries[origin]
	if e == nil {
		return nil
	}

	v := e.Value.(clientHintEntry)
	if !v.expires.IsZero() && !now.Before(v.expires) {
		delete(s.entries, origin)
		s.lru.Remove(e)
		return nil
	}

	s.lru.MoveToFront(e)

	return append([]string(nil), v.hints...)
}

func (s *clientHintStore) put(origin string, hints []string) {
	now := s.clock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if e := s.entries[origin]; e != nil {
		s.lru.Remove(e)
		delete(s.entries, origin)
	}

	if len(hints) == 0 {
		return
	}

	v := clientHintEntry{origin: origin, hints: append([]string(nil), hints...)}
	if s.lifetime > 0 {
		v.expires = now.Add(s.lifetime)
	}

	s.entries[origin] = s.lru.PushFront(v)
	if len(s.entries) > s.capacity {
		e := s.lru.Back()
		delete(s.entries, e.Value.(clientHintEntry).origin)
		s.lru.Remove(e)
	}
}

func clientHintOrigin(u *url.URL) (string, bool) { return origin.Key(u) }

func clientHintTrustworthy(u *url.URL) bool {
	_, valid := clientHintOrigin(u)
	return valid && origin.TrustworthyHTTP(u)
}
