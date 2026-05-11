package retryafter_test

import (
	"testing"
	"time"

	"github.com/enetx/surf/internal/retryafter"
)

func TestParse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		value   string
		wantDur time.Duration
		wantOK  bool
	}{
		{"empty string", "", 0, false},
		{"whitespace only", "   ", 0, false},
		{"zero seconds", "0", 0, true},
		{"positive seconds", "120", 120 * time.Second, true},
		{"negative seconds rejected", "-5", 0, false},
		{"fractional seconds rejected", "1.5", 0, false},
		{"whitespace tolerated around int", "  5  ", 5 * time.Second, true},
		{"IMF-fixdate future +30s", "Mon, 11 May 2026 12:00:30 GMT", 30 * time.Second, true},
		{"RFC 850 future +30s", "Monday, 11-May-26 12:00:30 GMT", 30 * time.Second, true},
		{"ANSI C asctime future +30s", "Mon May 11 12:00:30 2026", 30 * time.Second, true},
		{"past HTTP-date clamped to zero", "Wed, 21 Oct 2020 07:28:00 GMT", 0, true},
		{"malformed garbage", "tomorrow", 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotDur, gotOK := retryafter.Parse(tc.value, now)
			if gotOK != tc.wantOK || gotDur != tc.wantDur {
				t.Errorf("Parse(%q) = (%v, %v); want (%v, %v)",
					tc.value, gotDur, gotOK, tc.wantDur, tc.wantOK)
			}
		})
	}
}
