package desktop

import (
	"github.com/enetx/surf/pkg/tlscache"
	"github.com/enetx/surf/profiles"
)

// ConfigureSessionCache follows SSLTokensCache's ten-token expiry-ordered queue.
// Tokens, including TLS 1.2 external tokens, are removed when retrieved.
// The key ceiling is Surf's runtime bound; Firefox bounds compressed bytes.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/base/SSLTokensCache.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/modules/libpref/init/StaticPrefList.yaml
func ConfigureSessionCache(cache *profiles.SessionCacheConfig) {
	cache.Capacity(1024).TicketsPerKey(10).
		Order(tlscache.EarliestExpiryFirst)
}
