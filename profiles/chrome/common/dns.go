package common

import "time"

// HTTPSRecordsWait follows Chromium's opportunistic ECH DNS task. The timer
// begins after address queries finish, using 20% of their duration, with 5 ms
// and 50 ms bounds. These defaults apply to both secure and insecure DNS.
// Strict ECH uses no supplemental deadline (a nil wait policy).
// https://chromium.googlesource.com/chromium/src/+/158.0.8127.18/net/base/features.cc
// https://chromium.googlesource.com/chromium/src/+/158.0.8127.18/net/dns/host_resolver_dns_task.cc
func HTTPSRecordsWait(addressLookup time.Duration) time.Duration {
	return min(50*time.Millisecond, max(5*time.Millisecond, addressLookup/5))
}
