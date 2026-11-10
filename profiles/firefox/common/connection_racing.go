package common

import (
	"time"

	"github.com/enetx/surf/profiles"
)

// ConnectionRacing follows the pending HTTP/3 transaction's TCP backup timer.
// HTTPS DNS records and Happy Eyeballs have separate browser policies.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/modules/libpref/init/StaticPrefList.yaml
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp
func ConnectionRacing(profiles.ConnectionRacingInfo) time.Duration { return 100 * time.Millisecond }
