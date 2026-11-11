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

// Keep only a cursor into the application's existing TLS cache. A completed
// connection alone cannot change the initial version: a reusable ticket must
// still exist. Origins include the port and use the original, pre-Alt-Svc name.
type sessionVersions struct {
	mu      sync.Mutex
	entries map[string]sessionVersionEntry
	serial  uint64
	closed  bool
}

type sessionVersionEntry struct {
	key    string
	ticket [32]byte
	serial uint64
}

func (h *sessionVersions) prepare(origin string, tlsConfig *tls.Config, config *quic.Config) (*tls.Config, *quic.Config) {
	if tlsConfig == nil || tlsConfig.SessionTicketsDisabled || tlsConfig.ClientSessionCache == nil {
		return tlsConfig, config
	}
	origin = strings.ToLower(origin)
	h.mu.Lock()
	entry := h.entries[origin]
	closed := h.closed
	h.mu.Unlock()
	if closed {
		return tlsConfig, config
	}
	tlsConfig = tlsConfig.Clone()
	cache := tlsConfig.ClientSessionCache
	wrapped := &versionSessionCache{ClientSessionCache: cache, history: h, origin: origin}
	tlsConfig.ClientSessionCache = wrapped
	if entry.key == "" {
		return tlsConfig, config
	}
	session, ok := cache.Get(entry.key)
	ticket, identified := sessionTicketID(session)
	version, marked := quic.SessionVersion(session)
	from, until, usable := quictls.SessionLifetime(session)
	now := time.Now()
	if tlsConfig.Time != nil {
		now = tlsConfig.Time()
	}
	if !ok || !identified || ticket != entry.ticket || !marked || !usable || now.Before(from) || now.After(until) {
		return tlsConfig, config
	}
	if config == nil || !slices.Contains(config.Versions, version) {
		return tlsConfig, config
	}
	// The selection lookup may consume a ticket in an application-supplied
	// single-use cache. Hand the selected state to TLS exactly once.
	wrapped.selectedKey, wrapped.selected = entry.key, session
	if config.Versions[0] == version {
		return tlsConfig, config
	}
	config = quictransport.CloneConfig(config)
	index := slices.Index(config.Versions, version)
	copy(config.Versions[1:index+1], config.Versions[:index])
	config.Versions[0] = version
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
	// Publish the cursor before the user's Put callback can signal a stored
	// ticket. Readers still require that exact ticket to be visible in Get.
	// The callback runs after unlocking, allowing reentrant cache implementations.
	defer c.ClientSessionCache.Put(key, session)
	h := c.history
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	if session == nil {
		if h.entries[c.origin].key == key {
			delete(h.entries, c.origin)
		}
		return
	}
	if _, ok := quic.SessionVersion(session); !ok {
		return
	}
	ticket, ok := sessionTicketID(session)
	if !ok {
		return
	}
	if h.entries == nil {
		h.entries = make(map[string]sessionVersionEntry)
	}
	if _, exists := h.entries[c.origin]; !exists && len(h.entries) >= 256 {
		oldest, serial := "", ^uint64(0)
		for origin, entry := range h.entries {
			if entry.serial < serial {
				oldest, serial = origin, entry.serial
			}
		}
		delete(h.entries, oldest)
	}
	h.serial++
	h.entries[c.origin] = sessionVersionEntry{key: key, ticket: ticket, serial: h.serial}
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
