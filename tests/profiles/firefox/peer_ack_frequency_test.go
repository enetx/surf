package firefox_test

import (
	"math"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	firefoxquic "github.com/enetx/surf/profiles/firefox/quic"
)

func TestFirefoxPeerAckFrequencyNeqoVectors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                                  string
		window, mtu, tolerance                uint64
		rtt, minimum, currentDelay, wantDelay time.Duration
		currentPackets                        uint64
		update                                bool
	}{
		{"initial", 12000, 1200, 2, 20 * time.Millisecond, time.Millisecond, 25 * time.Millisecond, 5 * time.Millisecond, 2, true},
		{"window", 48000, 1200, 10, 12 * time.Millisecond, time.Millisecond, 3 * time.Millisecond, 3 * time.Millisecond, 2, true},
		{"unchanged", 48000, 1200, 10, 12 * time.Millisecond, time.Millisecond, 3 * time.Millisecond, 3 * time.Millisecond, 10, false},
		{"limits", math.MaxUint64, 1200, 256, time.Second, time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond, 2, true},
		{"peer-floor", 12000, 1200, 2, time.Millisecond, 2 * time.Millisecond, 25 * time.Millisecond, 2 * time.Millisecond, 2, true},
		{"low-hysteresis-boundary", 12000, 1200, 2, 40 * time.Millisecond, time.Millisecond, 7500 * time.Microsecond, 10 * time.Millisecond, 2, false},
		{"low-hysteresis-outside", 12000, 1200, 2, 40 * time.Millisecond, time.Millisecond, 7499 * time.Microsecond, 10 * time.Millisecond, 2, true},
		{"high-hysteresis-boundary", 12000, 1200, 2, 40 * time.Millisecond, time.Millisecond, 12500 * time.Microsecond, 10 * time.Millisecond, 2, false},
		{"high-hysteresis-outside", 12000, 1200, 2, 40 * time.Millisecond, time.Millisecond, 12501 * time.Microsecond, 10 * time.Millisecond, 2, true},
		{"microsecond-rounding", 12000, 1200, 2, 39999 * time.Nanosecond, 0, 11 * time.Microsecond, 9 * time.Microsecond, 2, false},
		{"large-peer-minimum", 12000, 1200, 2, time.Millisecond, 60 * time.Millisecond, 60 * time.Millisecond, 60 * time.Millisecond, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := quic.PeerAckFrequencyInfo{CongestionWindow: tc.window, MaxDatagramSize: tc.mtu,
				SmoothedRTT: tc.rtt, PeerMinAckDelay: tc.minimum,
				Current: quic.PeerAckFrequency{AckElicitingThreshold: tc.currentPackets, MaxAckDelay: tc.currentDelay}}
			got, update := firefoxquic.PeerAckFrequency(info)
			if got.AckElicitingThreshold != tc.tolerance || got.MaxAckDelay != tc.wantDelay || got.IgnoreOrder || update != tc.update {
				t.Fatalf("Neqo policy: got %+v, update=%v; want tolerance=%d delay=%s update=%v", got, update, tc.tolerance, tc.wantDelay, tc.update)
			}
		})
	}
}

func FuzzFirefoxPeerAckFrequencyBounds(f *testing.F) {
	f.Add(uint64(12000), uint64(1200), int64(20*time.Millisecond), uint32(1000))
	f.Add(uint64(math.MaxUint64), uint64(0), int64(math.MaxInt64), uint32(100000))
	f.Fuzz(func(t *testing.T, window, mtu uint64, rtt int64, minimum uint32) {
		minDelay := time.Duration(minimum%16000000) * time.Microsecond
		got, _ := firefoxquic.PeerAckFrequency(quic.PeerAckFrequencyInfo{CongestionWindow: window, MaxDatagramSize: mtu,
			SmoothedRTT: time.Duration(rtt), PeerMinAckDelay: minDelay,
			Current: quic.PeerAckFrequency{AckElicitingThreshold: 2, MaxAckDelay: 25 * time.Millisecond}})
		if got.AckElicitingThreshold < 2 || got.AckElicitingThreshold > 256 || got.MaxAckDelay < minDelay || got.MaxAckDelay%time.Microsecond != 0 || got.IgnoreOrder {
			t.Fatalf("invalid Firefox policy result: %+v", got)
		}
	})
}
