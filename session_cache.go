package surf

import (
	"crypto/tls"
	"fmt"
	"math"
	"time"

	"github.com/enetx/surf/internal/quictls"
	"github.com/enetx/surf/pkg/tlscache"
	"github.com/enetx/surf/profiles"
)

// SessionTicketOrder selects the next available ticket for a connection.
type SessionTicketOrder = tlscache.Order

const (
	// SessionTicketNewestFirst selects the most recently received ticket.
	SessionTicketNewestFirst = tlscache.NewestFirst
	// SessionTicketEarliestExpiryFirst selects the nearest expiry, with new equal-expiry tickets first.
	SessionTicketEarliestExpiryFirst = tlscache.EarliestExpiryFirst
)

// SessionCache configures TLS ticket caching through the client builder.
// Settings apply to TCP and QUIC by default; TCP, QUIC and Both select the
// transports affected by subsequent settings. Set returns the parent builder.
// Session separately enables cookie persistence.
type SessionCache struct {
	builder    *Builder           // Parent returned by Set.
	tcp, quic  sessionCachePolicy // Independent policy and state for each transport.
	scope      uint8              // Transport selection for subsequent fluent calls.
	registered bool               // The parent has one policy-application middleware.
	applied    bool               // Both caches resolved successfully during the current Build.
}

// sessionCachePolicy keeps explicit choices separate from a Build result.
type sessionCachePolicy struct {
	overrides   []func(*profiles.SessionCacheConfig) // Applied after the browser policy.
	customCache tls.ClientSessionCache               // Application choice; nil can explicitly disable caching.
	cache       tls.ClientSessionCache               // Resolved backend for the current client build.
	enabled     bool                                 // This transport received an explicit cache setting.
	custom      bool                                 // Custom was called, including with nil.
}

const (
	sessionCacheTCP uint8 = 1 << iota
	sessionCacheQUIC
	sessionCacheBoth = sessionCacheTCP | sessionCacheQUIC
)

// SessionCache starts the nested ticket-cache builder. Browser defaults are
// applied first, followed by explicit settings, regardless of chain order.
// Each call selects both transports; TCP and QUIC narrow subsequent settings.
func (b *Builder) SessionCache() *SessionCache {
	if b.sessionCacheSettings == nil {
		b.sessionCacheSettings = &SessionCache{builder: b, scope: sessionCacheBoth}
	}

	b.sessionCacheSettings.scope = sessionCacheBoth

	return b.sessionCacheSettings
}

// TCP selects the HTTP/1 and HTTP/2 TLS cache for subsequent settings.
func (s *SessionCache) TCP() *SessionCache { s.scope = sessionCacheTCP; return s }

// QUIC selects the HTTP/3 TLS cache for subsequent settings.
func (s *SessionCache) QUIC() *SessionCache { s.scope = sessionCacheQUIC; return s }

// Both applies subsequent settings to independent TCP and QUIC caches.
func (s *SessionCache) Both() *SessionCache { s.scope = sessionCacheBoth; return s }

// Capacity bounds server keys, including recently consumed-ticket records.
// The valid range is 1..1048576. The generic default is 64; the Chrome/Firefox
// policies use 1024. Custom caches control their own limits.
func (s *SessionCache) Capacity(keys int) *SessionCache {
	return s.configure(func(b *profiles.SessionCacheConfig) { b.Capacity(keys) })
}

// TicketsPerKey bounds available tickets for each TLS cache key, in 1..1024.
// The generic default is one; Chrome keeps two and Firefox keeps ten.
func (s *SessionCache) TicketsPerKey(tickets int) *SessionCache {
	return s.configure(func(b *profiles.SessionCacheConfig) { b.TicketsPerKey(tickets) })
}

// Order selects the next ticket. Chrome and the generic cache select newest
// first; Firefox selects the nearest expiry, with new equal-expiry tickets first.
func (s *SessionCache) Order(order SessionTicketOrder) *SessionCache {
	return s.configure(func(b *profiles.SessionCacheConfig) { b.Order(order) })
}

// ReuseTLS12 keeps legacy tickets reusable. TLS 1.3 tickets are consumed once.
// Enabled by the Chrome TCP policy; disabled by the other current policies.
func (s *SessionCache) ReuseTLS12(enabled bool) *SessionCache {
	return s.configure(func(b *profiles.SessionCacheConfig) { b.ReuseTLS12(enabled) })
}

// DiscardOnExpiry removes the entire key when its next ticket expires.
// Otherwise individual expiry handling follows SkipExpired. The Chrome QUIC
// policy enables whole-entry expiry; the generic and Firefox policies do not.
func (s *SessionCache) DiscardOnExpiry(enabled bool) *SessionCache {
	return s.configure(func(b *profiles.SessionCacheConfig) { b.DiscardOnExpiry(enabled) })
}

// SkipExpired continues lookup after removing an expired ticket. False returns
// a miss and leaves the next ticket for a later connection. DiscardOnExpiry
// takes precedence when enabled.
func (s *SessionCache) SkipExpired(enabled bool) *SessionCache {
	return s.configure(func(b *profiles.SessionCacheConfig) { b.SkipExpired(enabled) })
}

// ClearEarlyDataOnReject disables early data on remaining QUIC tickets after
// rejection, while retaining ordinary TLS resumption. Enabled by the Chrome
// QUIC policy; disabled by the generic and Firefox policies.
func (s *SessionCache) ClearEarlyDataOnReject(enabled bool) *SessionCache {
	return s.configure(func(b *profiles.SessionCacheConfig) { b.ClearEarlyDataOnReject(enabled) })
}

// Clock overrides ticket validity time. By default the cache uses TLSConfig.Time.
// Nil selects time.Now. This does not change the TLS engine's clock.
func (s *SessionCache) Clock(clock func() time.Time) *SessionCache {
	return s.configure(func(b *profiles.SessionCacheConfig) { b.Clock(clock) })
}

// Group invalidates older tickets when the returned compatibility group changes.
// The callback runs outside cache locks and must be concurrency safe; it must
// not modify the supplied session. Nil disables compatibility grouping.
func (s *SessionCache) Group(group func(*tls.ClientSessionState) string) *SessionCache {
	return s.configure(func(b *profiles.SessionCacheConfig) { b.Group(group) })
}

// Custom supplies an application cache for the selected transports. Its policy
// takes precedence over browser defaults and queue settings. Nil disables the
// selected caches. Native and browser TCP use a separate "tcp:" key namespace.
func (s *SessionCache) Custom(cache tls.ClientSessionCache) *SessionCache {
	s.each(func(p *sessionCachePolicy) {
		p.enabled, p.custom, p.customCache = true, true, cache
	})
	return s
}

// Set applies the accumulated policy and returns the client builder. Invalid
// capacities or ordering are returned by Builder.Build. Caching does not enable
// cookie persistence or override TLSConfig.SessionTicketsDisabled.
func (s *SessionCache) Set() *Builder {
	s.each(func(p *sessionCachePolicy) { p.enabled = true })
	s.register()

	return s.builder
}

func (s *SessionCache) configure(configure func(*profiles.SessionCacheConfig)) *SessionCache {
	s.each(func(p *sessionCachePolicy) {
		p.enabled = true
		p.overrides = append(p.overrides, configure)
	})
	return s
}

func (s *SessionCache) each(apply func(*sessionCachePolicy)) {
	if s.scope&sessionCacheTCP != 0 {
		apply(&s.tcp)
	}

	if s.scope&sessionCacheQUIC != 0 {
		apply(&s.quic)
	}
}

// register resolves caches after ordinary client configuration and before the
// HTTP/3 and browser TCP transports take their snapshots. Repeated Set is safe.
func (s *SessionCache) register() {
	if !s.registered {
		s.registered = true
		s.builder.addCliMW(s.apply, math.MaxInt-2)
	}
}

// apply resolves both backends before publishing either, preserving application
// ownership and the original TLS config pointer.
func (s *SessionCache) apply(c *Client) error {
	s.applied = false
	source := c.GetTLSConfig()
	_, automatic := source.ClientSessionCache.(*defaultSessionCache)
	automatic = automatic || source.ClientSessionCache == nil && s.builder.sessionEnabled

	tcp, err := s.tcp.resolve(s.builder.configureTCPSessionCache, source, automatic)
	if err != nil {
		return fmt.Errorf("TCP session cache: %w", err)
	}

	quic, err := s.quic.resolve(s.builder.configureQUICSessionCache, source, automatic)
	if err != nil {
		return fmt.Errorf("QUIC session cache: %w", err)
	}

	s.tcp.cache, s.quic.cache = tcp, quic
	source.ClientSessionCache = quictls.TCPCache(tcp)

	if !s.tcp.custom && (s.tcp.enabled || automatic) {
		source.ClientSessionCache = &defaultSessionCache{source.ClientSessionCache}
	}

	s.applied = true

	return nil
}

// resolve uses explicit application state unchanged, or creates an owned cache
// from generic defaults, the selected browser policy and user overrides.
func (p *sessionCachePolicy) resolve(
	configure func(*profiles.SessionCacheConfig),
	source *tls.Config,
	automatic bool,
) (tls.ClientSessionCache, error) {
	if p.custom {
		return p.customCache, nil
	}

	if !p.enabled && !automatic {
		return quictls.BaseTCPCache(source.ClientSessionCache), nil
	}

	if configure == nil && len(p.overrides) == 0 && !p.enabled {
		return tls.NewLRUClientSessionCache(0), nil
	}

	settings := tlscache.New().Clock(source.Time)

	if configure != nil {
		configure(settings)
	}

	for _, override := range p.overrides {
		override(settings)
	}

	return settings.Build().Result()
}

// Marks only Surf-owned defaults. A supplied application cache is never replaced
// with a browser queue merely because an impersonation profile is selected.
type defaultSessionCache struct{ tls.ClientSessionCache }
