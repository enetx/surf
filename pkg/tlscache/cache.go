package tlscache

import (
	"container/list"
	"crypto/tls"
	"slices"
	"sync"
	"time"

	"github.com/enetx/surf/internal/tlsstate"
)

// Cache is a concurrency-safe ticket queue. Get consumes TLS 1.3 tickets;
// Put(key, nil) removes all remembered state for that key. A recently consumed
// ticket cannot be resurrected by a TLS early-data rejection update.
type Cache struct {
	mu     sync.Mutex
	policy Builder
	keys   map[string]*list.Element
	lru    *list.List
}

type entry struct {
	key, group string
	queue      []ticket
	consumed   [][32]byte
}

type ticket struct {
	state       *tls.ClientSessionState
	version     uint16
	from, until time.Time
	id          [32]byte
}

func newCache(policy Builder) *Cache {
	return &Cache{policy: policy, keys: make(map[string]*list.Element), lru: list.New()}
}

// Put stores a valid ticket, replacing incompatible queued state when Group
// changes. Nil removes the key and its consumption history. Recently consumed
// identities are ignored, including TLS early-data rejection updates.
func (c *Cache) Put(key string, state *tls.ClientSessionState) {
	if state == nil {
		c.mu.Lock()
		if element := c.keys[key]; element != nil {
			c.remove(element)
		}
		c.mu.Unlock()
		return
	}
	version, from, until, id, ok := tlsstate.SessionInfo(state)
	if !ok {
		return
	}
	now := c.policy.clock()
	if now.Before(from) || !now.Before(until) {
		return
	}
	group := ""
	if c.policy.group != nil {
		group = c.policy.group(state)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element := c.keys[key]
	if element == nil {
		if len(c.keys) >= c.policy.capacity {
			c.remove(c.lru.Back())
		}
		element = c.lru.PushFront(&entry{key: key, group: group})
		c.keys[key] = element
	}
	c.lru.MoveToFront(element)
	e := element.Value.(*entry)
	if slices.Contains(e.consumed, id) {
		return
	}
	if e.group != group {
		e.queue = nil
		e.group = group
	}
	e.queue = slices.DeleteFunc(e.queue, func(t ticket) bool { return t.id == id || !now.Before(t.until) })
	if c.policy.reuseTLS12 && len(e.queue) > 0 && e.queue[0].version < tls.VersionTLS13 {
		e.queue[0] = ticket{}
		e.queue = e.queue[1:]
	}
	if len(e.queue) == c.policy.tickets {
		if c.policy.order == EarliestExpiryFirst {
			e.queue[0] = ticket{}
			e.queue = e.queue[1:]
		} else {
			e.queue[len(e.queue)-1] = ticket{}
			e.queue = e.queue[:len(e.queue)-1]
		}
	}
	e.queue = append([]ticket{{state: state, version: version, from: from, until: until, id: id}}, e.queue...)
	if c.policy.order == EarliestExpiryFirst {
		// Stable insertion leaves a newly received equal-expiry token first,
		// matching Firefox TokenCacheEntry::AddRecord.
		slices.SortStableFunc(e.queue, func(a, b ticket) int { return a.until.Compare(b.until) })
	}
}

// Get selects the next usable ticket according to Order and the expiry policy.
// TLS 1.3 tickets are consumed once; ReuseTLS12 controls legacy ticket reuse.
func (c *Cache) Get(key string) (*tls.ClientSessionState, bool) {
	return c.lookup(key, true)
}

// Peek inspects the next valid ticket without consuming it. The returned state
// is read-only; callers must not use it to bypass single-use TLS selection.
func (c *Cache) Peek(key string) (*tls.ClientSessionState, bool) {
	return c.lookup(key, false)
}

func (c *Cache) lookup(key string, consume bool) (*tls.ClientSessionState, bool) {
	now := c.policy.clock()
	c.mu.Lock()
	defer c.mu.Unlock()
	element := c.keys[key]
	if element == nil {
		return nil, false
	}
	c.lru.MoveToFront(element)
	e := element.Value.(*entry)
	for len(e.queue) > 0 {
		t := e.queue[0]
		if now.Before(t.from) || !now.Before(t.until) {
			if c.policy.discardOnExpiry {
				c.remove(element)
				return nil, false
			}
			e.queue[0] = ticket{}
			e.queue = e.queue[1:]
			if !c.policy.skipExpired {
				return nil, false
			}
			continue
		}
		if consume && (t.version >= tls.VersionTLS13 || !c.policy.reuseTLS12) {
			e.queue[0] = ticket{}
			e.queue = e.queue[1:]
			e.consumed = append(e.consumed, t.id)
			if len(e.consumed) > 2*c.policy.tickets {
				e.consumed = e.consumed[1:]
			}
		}
		return t.state, true
	}
	return nil, false
}

// Clear releases all queued and consumed state.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.keys)
	c.lru.Init()
}

// RejectEarlyData preserves queued TLS resumption while disabling their early
// data, when the configured policy enables that behavior. Selected tickets are
// already consumed and are not inserted again.
func (c *Cache) RejectEarlyData(key string) {
	if !c.policy.clearEarlyData {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element := c.keys[key]
	if element == nil {
		return
	}
	e := element.Value.(*entry)
	kept := e.queue[:0]
	for _, t := range e.queue {
		label, state, err := t.state.ResumptionState()
		if err != nil {
			continue
		}
		data, err := state.Bytes()
		if err != nil {
			continue
		}
		clone, err := tls.ParseSessionState(data)
		if err != nil {
			continue
		}
		clone.EarlyData = false
		updated, err := tls.NewResumptionState(label, clone)
		if err != nil {
			continue
		}
		t.state = updated
		kept = append(kept, t)
	}
	clear(e.queue[len(kept):])
	e.queue = kept
}

func (c *Cache) remove(element *list.Element) {
	delete(c.keys, element.Value.(*entry).key)
	c.lru.Remove(element)
}
