package common

import (
	"testing"
	"time"
)

func TestHTTPSRecordsWaitBounds(t *testing.T) {
	for _, tc := range []struct{ lookup, extra time.Duration }{
		{0, 5 * time.Millisecond}, {20 * time.Millisecond, 5 * time.Millisecond},
		{100 * time.Millisecond, 20 * time.Millisecond}, {time.Second, 50 * time.Millisecond},
	} {
		if got := HTTPSRecordsWait(tc.lookup); got != tc.extra {
			t.Fatalf("lookup %s: supplemental wait %s != %s", tc.lookup, got, tc.extra)
		}
	}
}
