package h3transport

import (
	"crypto/sha256"
	"crypto/tls"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/enetx/quic-go"
	quictransport "github.com/enetx/surf/internal/quic"
	"github.com/enetx/surf/internal/quictls"
)

// Retain cursors, never a second PSK cache. Origins include the original port,
// before Alt-Svc routing. Consuming a newest ticket must not hide older tickets.
type sessionVersions struct {
	mu             sync.Mutex
	entries        map[string]sessionVersionEntry
	serial         uint64
	closed         bool
	restoreVersion bool
	rttPrecision   time.Duration
}
type sessionVersionEntry struct {
	tickets []sessionTicketRef
	serial  uint64
}
type sessionTicketRef struct {
	key   string
	id    [32]byte
	until time.Time
}

func (h *sessionVersions) prepare(origin string, tlsConfig *tls.Config, config *quic.Config) (*tls.Config, *quic.Config) {
	if tlsConfig == nil || tlsConfig.SessionTicketsDisabled || tlsConfig.ClientSessionCache == nil {
		return tlsConfig, config
	}
	origin = strings.ToLower(origin)
	h.mu.Lock()
	refs, closed := slices.Clone(h.entries[origin].tickets), h.closed
	h.mu.Unlock()
	if closed {
		return tlsConfig, config
	}
	tlsConfig = tlsConfig.Clone()
	cache := tlsConfig.ClientSessionCache
	wrapped := &versionSessionCache{ClientSessionCache: cache, history: h, origin: origin}
	tlsConfig.ClientSessionCache = wrapped
	now := time.Now()
	if tlsConfig.Time != nil {
		now = tlsConfig.Time()
	}
	seen := make(map[string]bool)
	for _, ref := range refs {
		if seen[ref.key] || !now.Before(ref.until) {
			continue
		}
		seen[ref.key] = true
		session, ok := cache.Get(ref.key)
		ticket, identified := sessionTicketID(session)
		info, marked := quic.ClientSessionMetadata(session)
		from, until, usable := quictls.SessionLifetime(session)
		// Put publishes ownership before storing a ticket in the application
		// cache. Get can therefore select a newer ticket than our key snapshot.
		// Check live ownership after Get, without holding a lock across callbacks.
		h.mu.Lock()
		known := !h.closed && slices.ContainsFunc(h.entries[origin].tickets, func(r sessionTicketRef) bool { return r.key == ref.key && r.id == ticket })
		h.mu.Unlock()
		if !ok || !identified || !known || !marked || !usable || now.Before(from) || !now.Before(until) {
			continue
		}
		if config == nil || !slices.Contains(config.Versions, info.Version) {
			continue
		}
		if !h.restoreVersion && config.Versions[0] != info.Version {
			continue
		}
		// Hand the selected state to TLS exactly once. Competing address candidates
		// must obtain another ticket through the application's authoritative cache.
		wrapped.selectedKey, wrapped.selected = ref.key, session
		measured := info.RTT
		if h.rttPrecision > 0 {
			measured = measured.Truncate(h.rttPrecision)
		} else {
			measured = 0
		}
		if config.Versions[0] == info.Version && measured == 0 {
			return tlsConfig, config
		}
		config = quictransport.CloneConfig(config)
		if h.restoreVersion {
			index := slices.Index(config.Versions, info.Version)
			copy(config.Versions[1:index+1], config.Versions[:index])
			config.Versions[0] = info.Version
		}
		if measured > 0 {
			if config.ClientHandshake == nil {
				config.ClientHandshake = new(quic.ClientHandshake)
			}
			config.ClientHandshake.InitialRTT = measured
		}
		return tlsConfig, config
	}
	return tlsConfig, config
}

func (h *sessionVersions) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	h.entries = nil
}

type versionSessionCache struct {
	tls.ClientSessionCache
	mu          sync.Mutex
	selectedKey string
	selected    *tls.ClientSessionState
	history     *sessionVersions
	origin      string
}

func (c *versionSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	if key == c.selectedKey && c.selected != nil {
		session := c.selected
		c.selected = nil
		c.mu.Unlock()
		return session, true
	}
	c.mu.Unlock()
	return c.ClientSessionCache.Get(key)
}
func (c *versionSessionCache) Put(key string, session *tls.ClientSessionState) {
	// Publish before a user callback can signal a completed write, and never
	// retain history locks across an application-owned cache callback.
	defer c.ClientSessionCache.Put(key, session)
	h := c.history
	var ref sessionTicketRef
	if session != nil {
		if _, ok := quic.SessionVersion(session); !ok {
			return
		}
		id, ok := sessionTicketID(session)
		_, until, usable := quictls.SessionLifetime(session)
		if !ok || !usable {
			return
		}
		ref = sessionTicketRef{key: key, id: id, until: until}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	entry := h.entries[c.origin]
	if session == nil {
		entry.tickets = slices.DeleteFunc(entry.tickets, func(r sessionTicketRef) bool { return r.key == key })
		if len(entry.tickets) == 0 {
			delete(h.entries, c.origin)
		} else {
			h.entries[c.origin] = entry
		}
		return
	}
	if h.entries == nil {
		h.entries = make(map[string]sessionVersionEntry)
	}
	if _, exists := h.entries[c.origin]; !exists && len(h.entries) >= 256 {
		oldest, serial := "", ^uint64(0)
		for origin, cached := range h.entries {
			if cached.serial < serial {
				oldest, serial = origin, cached.serial
			}
		}
		delete(h.entries, oldest)
	}
	entry.tickets = slices.DeleteFunc(entry.tickets, func(r sessionTicketRef) bool { return r.id == ref.id && r.key == key })
	entry.tickets = append([]sessionTicketRef{ref}, entry.tickets...)
	// Bound cursor bookkeeping independently of the application's cache.
	if len(entry.tickets) > 32 {
		entry.tickets = entry.tickets[:32]
	}
	slices.SortStableFunc(entry.tickets, func(a, b sessionTicketRef) int { return a.until.Compare(b.until) })
	h.serial++
	entry.serial = h.serial
	h.entries[c.origin] = entry
}
func sessionTicketID(session *tls.ClientSessionState) ([32]byte, bool) {
	if session == nil {
		return [32]byte{}, false
	}
	ticket, _, err := session.ResumptionState()
	if err != nil || len(ticket) == 0 {
		return [32]byte{}, false
	}
	return sha256.Sum256(ticket), true
}
