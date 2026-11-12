package common

import (
	"github.com/enetx/surf/pkg/tlscache"
	"github.com/enetx/surf/profiles"
)

// ConfigureTCPSessionCache follows SSLClientSessionCache::Entry::Push/Pop:
// two newest TLS 1.3 tickets, consumed once; TLS 1.2 remains reusable.
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/ssl/ssl_client_session_cache.cc
func ConfigureTCPSessionCache(cache *profiles.SessionCacheConfig) {
	cache.Capacity(1024).TicketsPerKey(2).
		Order(tlscache.NewestFirst).ReuseTLS12(true).
		DiscardOnExpiry(false).SkipExpired(false)
}
