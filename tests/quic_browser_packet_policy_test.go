package surf_test

import (
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf"
	chrome "github.com/enetx/surf/profiles/chrome/quic"
	firefox "github.com/enetx/surf/profiles/firefox/quic"
	"github.com/stretchr/testify/require"
)

func TestBrowserPacketNumberLengths(t *testing.T) {
	for _, tc := range []struct {
		pn, least, flight uint64
		ack               int64
		chrome, firefox   uint8
	}{
		{1, 1, 10, -1, 1, 1}, {63, 0, 10, -1, 1, 1}, {64, 0, 10, -1, 2, 1},
		{1000, 999, 63, 999, 1, 1}, {1000, 999, 64, 999, 2, 1},
		{127, 0, 1, 0, 2, 1}, {128, 0, 1, 0, 2, 2},
		{65536, 65535, 1, 65535, 1, 1}, {1 << 22, 0, 1, -1, 4, 3}, {1 << 24, 0, 1, -1, 4, 4},
	} {
		info := quic.PacketNumberLengthInfo{PacketNumber: tc.pn, LeastUnacknowledged: tc.least, MaxPacketsInFlight: tc.flight, LargestAcknowledged: tc.ack}
		require.Equal(t, tc.chrome, chrome.PacketNumberLength(info), "Chrome %+v", info)
		require.Equal(t, tc.firefox, firefox.PacketNumberLength(info), "Firefox %+v", info)
	}
}

func TestChromeCoalescedPacketNumberLengths(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		pn, least, full, soft uint64
		want                  uint8
	}{
		{"first Initial", 1, 1, 37, 0, 1},
		{"second Initial after soft limit", 2, 1, 37, 178, 2},
		{"full datagram restored", 3, 1, 37, 0, 1},
		{"soft limit below full estimate", 3, 1, 64, 37, 2},
		{"one-byte boundary", 2, 1, 37, 63, 1},
		{"two-byte boundary", 2, 1, 37, 64, 2},
		{"three-byte boundary", 2, 1, 37, 16384, 3},
		{"outstanding range still wins", 64, 0, 1, 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := quic.PacketNumberLengthInfo{
				PacketNumber: tc.pn, LeastUnacknowledged: tc.least,
				LargestAcknowledged: -1, MaxPacketsInFlight: tc.full,
				CoalescedMaxPacketsInFlight: tc.soft,
			}
			require.Equal(t, tc.want, chrome.PacketNumberLength(info))
			withoutSoftLimit := info
			withoutSoftLimit.CoalescedMaxPacketsInFlight = 0
			require.Equal(t, firefox.PacketNumberLength(withoutSoftLimit), firefox.PacketNumberLength(info),
				"Firefox does not use Chromium's coalescing estimate")
		})
	}
}

func TestFirefoxAckProbeBoundaries(t *testing.T) {
	for _, count := range []uint64{0, 15, 16, 199, 200, 201} {
		deadline := 200 * time.Millisecond
		if count >= 200 {
			deadline = 100 * time.Millisecond
		}
		for _, elapsed := range []time.Duration{deadline - time.Nanosecond, deadline, deadline + time.Nanosecond} {
			info := quic.AckProbeInfo{OutstandingPackets: count, HasLastAckEliciting: true, SinceLastAckEliciting: elapsed, PTO: 100 * time.Millisecond}
			require.Equal(t, count >= 16 && elapsed > deadline, firefox.AckProbe(info), "%+v", info)
			info.HasLastAckEliciting = false
			require.False(t, firefox.AckProbe(info))
		}
	}
	require.False(t, firefox.AckProbe(quic.AckProbeInfo{OutstandingPackets: 200, HasLastAckEliciting: true, SinceLastAckEliciting: time.Second}))
	// Each public probe selector replaces the previously selected mode.
	client := surf.NewClient().Builder().ForceHTTP3().QUICSettings().
		AckOnlyMaxDataThreshold(19).AckProbePolicy(firefox.AckProbe).
		AckOnlyPingThreshold(2).AckProbePolicy(firefox.AckProbe).
		AckOnlyMaxDataThreshold(19).PacketNumberLengthPolicy(chrome.PacketNumberLength).
		Set().Build().Unwrap()
	client.Close()
}
