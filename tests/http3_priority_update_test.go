package surf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestHTTP3LivePriorityUpdates(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			peer := newH3Peer(t)
			b := surf.NewClient().Builder()
			if browser == "chrome" {
				b = b.Impersonate().Chrome()
			}
			if browser == "firefox" {
				b = b.Impersonate().Firefox()
			}
			client := b.ForceHTTP3().HTTP3Settings().Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			var updater *surf.HTTP3PriorityUpdater
			result := client.Get(g.String(peer.url)).HTTP3PriorityUpdates(func(p *surf.HTTP3PriorityUpdater) {
				updater = p
				if browser == "native" {
					require.NoError(t, p.Update(3, false))
				} else {
					require.NoError(t, p.Update(0, true))
				} // Initial value, even if profile sends no initial control frame.
				require.Error(t, p.Update(-1, false))
				require.Error(t, p.Update(8, false))
				var wg sync.WaitGroup
				for range 20 {
					wg.Go(func() { require.NoError(t, p.Update(2, true)) })
				}
				wg.Wait()
				require.NoError(t, p.Update(3, false))
				require.NoError(t, p.Update(3, false))
			}).WithContext(context.Background()).Do()
			require.False(t, result.IsErr(), "%v", result.Err())
			require.NotNil(t, updater)
			result.Ok().Body.String().Unwrap()
			require.ErrorIs(t, updater.Update(2, false), http3.ErrRequestCompleted)
			var values []string
			count := 2
			if browser == "chrome" {
				count++
			}
			for len(values) < count {
				frame := nextSurfControlFrame(t, peer)
				if frame.kind != 0xf0700 {
					continue
				}
				id, n, err := quicvarint.Parse(frame.payload)
				require.NoError(t, err)
				require.Zero(t, id)
				values = append(values, string(frame.payload[n:]))
			}
			want := []string{"u=2, i", ""}
			if browser == "chrome" {
				want = append([]string{"u=0, i"}, want...)
			}
			if browser == "firefox" {
				want[0] = "u=2,i"
			}
			require.Equal(t, want, values)
			select {
			case frame := <-peer.controlFrames:
				require.NotEqualValues(t, 0xf0700, frame.kind, "duplicate priority update")
			case <-time.After(20 * time.Millisecond):
			}
		})
	}
}

func TestHTTP3LivePriorityCancellation(t *testing.T) {
	peer := newH3Peer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := surf.NewClient().Builder().ForceHTTP3().HTTP3Settings().Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	var updater *surf.HTTP3PriorityUpdater
	result := client.Get(g.String(peer.url)).WithContext(ctx).HTTP3PriorityUpdates(func(p *surf.HTTP3PriorityUpdater) {
		updater = p
		cancel()
		require.True(t, errors.Is(p.Update(2, true), context.Canceled))
	}).Do()
	require.True(t, result.IsErr())
	require.NotNil(t, updater)
}
