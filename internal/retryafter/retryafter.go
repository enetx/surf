// Package retryafter parses values of the HTTP Retry-After header
// as defined by RFC 7231 §7.1.3.
//
// Two forms are recognised: an integer count of seconds (delay-seconds)
// and an HTTP-date in any of the three formats accepted by RFC 7231
// (IMF-fixdate, RFC 850, ANSI C asctime). The HTTP-date branch is
// handled by github.com/enetx/http.ParseTime, which mirrors the
// standard library's net/http.ParseTime.
package retryafter

import (
	"strconv"
	"strings"
	"time"

	"github.com/enetx/http"
)

// Parse interprets value as a Retry-After header field.
//
// On success it returns the wait duration and true. A successful parse of "0",
// a past HTTP-date, or any negative time.Until(parsed) is clamped to zero so
// that callers using max(retryWait, parsed) preserve their minimum floor.
//
// For missing, empty, malformed, fractional, or negative integer values it
// returns (0, false) so callers fall back to their own wait policy.
//
// The now argument is injected to keep HTTP-date arithmetic deterministic in
// tests; production callers pass time.Now() immediately before scheduling the
// timer.
//
// Multiple Retry-After headers are undefined by the RFC; callers must select
// a single value via http.Header.Get before calling Parse.
func Parse(value string, now time.Time) (time.Duration, bool) {
	v := strings.TrimSpace(value)
	if v == "" {
		return 0, false
	}

	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0, false
		}

		return time.Duration(n) * time.Second, true
	}

	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			return 0, true
		}

		return d, true
	}

	return 0, false
}
