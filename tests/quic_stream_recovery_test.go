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

func TestBrowserSTREAMLossRetentionBoundaries(t *testing.T) {
	for _, sample := range []struct {
		first, largest int64
		retain         bool
	}{{-1, 20, true}, {8, 7, true}, {8, 8, false}, {8, 9, false}} {
		require.Equal(t, sample.retain, chrome.StreamLossRetention(quic.StreamLossInfo{FirstPacketAfterLoss: sample.first, LargestAcknowledged: sample.largest}))
	}
	for _, age := range []time.Duration{0, time.Second - time.Nanosecond, time.Second, time.Second + time.Nanosecond} {
		require.Equal(t, age < time.Second, firefox.StreamLossRetention(quic.StreamLossInfo{TimeSinceLoss: age, ProbeTimeout: time.Second}))
	}
}

func TestSTREAMRecoveryFluentOptOut(t *testing.T) {
	peer := newH3Peer(t)
	q := surf.NewClient().Builder().Proxy("").Impersonate().Firefox().ForceHTTP3().QUICSettings().StreamDataRecovery(false).StreamLossRetention(nil)
	client := q.Set().Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	peer.request(t, client)
}
