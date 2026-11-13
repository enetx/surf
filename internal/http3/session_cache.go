package h3transport

import (
	"crypto/tls"
	"sync"

	"github.com/enetx/quic-go"
	quictransport "github.com/enetx/surf/internal/quic"
	"github.com/enetx/surf/pkg/tlscache"
)

// Track actual opaque cache keys through the engine's version namespace. This
// observes selection without replacing an application-owned cache or guessing
// TLS's key format. Address candidates share the origin's rejection policy.
type trackedTicketCache struct {
	*tlscache.Cache
	mu       sync.Mutex
	selected map[string]bool
}

func (c *trackedTicketCache) Get(key string) (*tls.ClientSessionState, bool) {
	state, ok := c.Cache.Get(key)
	if ok {
		c.mu.Lock()
		c.selected[key] = true
		c.mu.Unlock()
	}

	return state, ok
}

func trackTicketRejection(config *tls.Config, q *quic.Config) (*tls.Config, *quic.Config) {
	if config == nil {
		return config, q
	}

	queue, ok := config.ClientSessionCache.(*tlscache.Cache)
	if !ok {
		return config, q
	}

	tracked := &trackedTicketCache{Cache: queue, selected: make(map[string]bool)}

	config = config.Clone()
	config.ClientSessionCache = tracked

	q = quictransport.CloneConfig(q)
	if q == nil {
		q = quictransport.DefaultConfig()
	}

	if q.ClientHandshake == nil {
		q.ClientHandshake = new(quic.ClientHandshake)
	}

	previous := q.ClientHandshake.OnEarlyDataRejected

	q.ClientHandshake.OnEarlyDataRejected = func(conn *quic.Conn) {
		tracked.mu.Lock()
		keys := make([]string, 0, len(tracked.selected))
		for key := range tracked.selected {
			keys = append(keys, key)
		}
		tracked.mu.Unlock()

		for _, key := range keys {
			queue.RejectEarlyData(key)
		}

		if previous != nil {
			previous(conn)
		}
	}

	return config, q
}
