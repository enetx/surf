package surf_test

import (
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type versionTestCache struct {
	mu      sync.Mutex
	entries map[string]*tls.ClientSessionState
	stored  chan *tls.ClientSessionState
	consume bool
}

func (c *versionTestCache) Get(key string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state, ok := c.entries[key]
	if c.consume {
		delete(c.entries, key)
	}
	return state, ok
}

func (c *versionTestCache) Put(key string, state *tls.ClientSessionState) {
	c.mu.Lock()
	if c.entries == nil {
		c.entries = make(map[string]*tls.ClientSessionState)
	}
	if state == nil {
		delete(c.entries, key)
	} else {
		c.entries[key] = state
	}
	c.mu.Unlock()
	if state != nil {
		select {
		case c.stored <- state:
		default:
		}
	}
}

func TestQUICResumeVersionTicketLifecycle(t *testing.T) {
	for _, mode := range []string{"firefox", "native", "disabled", "evicted", "expired", "single-use", "tickets-disabled"} {
		t.Run(mode, func(t *testing.T) {
			peer := newH3PeerWithQPACK(t, nil, func(config *quic.Config) { config.Versions = []quic.Version{quic.Version2} })
			cache := &versionTestCache{stored: make(chan *tls.ClientSessionState, 8), consume: mode == "single-use"}
			b := surf.NewClient().Builder()
			if mode != "native" {
				b.Impersonate().Firefox()
			}
			// The native Go server does not implement authenticated compatible
			// negotiation. Start it directly at v2; selection from v1 is checked
			// with real tickets in internal/http3 and an independent packet peer.
			q := b.QUICSettings().Versions(quic.Version2, quic.Version1).CompatibleVersionNegotiation(true)
			if mode == "native" || mode == "disabled" {
				q.ResumeVersion(mode == "native")
			}
			var clock atomic.Int64
			clock.Store(time.Now().Unix())
			client := q.Set().ForceHTTP3().Proxy("").TLSConfig(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache,
				SessionTicketsDisabled: mode == "tickets-disabled", Time: func() time.Time { return time.Unix(clock.Load(), 0) },
			}).Timeout(10 * time.Second).Build().Unwrap()
			defer client.Close()
			peer.request(t, client)
			peer.packet.mu.Lock()
			first := peer.packet.initials[0].version
			peer.packet.mu.Unlock()
			require.EqualValues(t, quic.Version2, first, "a cold client starts with the configured version")
			if mode != "tickets-disabled" {
				select {
				case state := <-cache.stored:
					version, ok := quic.SessionVersion(state)
					require.True(t, ok)
					require.Equal(t, quic.Version2, version, "store the negotiated version, including after VN")
				case <-time.After(5 * time.Second):
					t.Fatal("no version-bearing session ticket")
				}
			}
			client.CloseIdleConnections()
			resetRTTWireCapture(peer)
			if mode == "evicted" {
				cache.mu.Lock()
				clear(cache.entries)
				cache.mu.Unlock()
			}
			if mode == "expired" {
				clock.Add(int64((8 * 24 * time.Hour) / time.Second))
			}
			peer.request(t, client)
			peer.packet.mu.Lock()
			second := peer.packet.initials[0].version
			peer.packet.mu.Unlock()
			require.EqualValues(t, quic.Version2, second)
			peer.mu.Lock()
			resumed := peer.resumed[len(peer.resumed)-1]
			peer.mu.Unlock()
			require.Equal(t, mode != "evicted" && mode != "expired" && mode != "tickets-disabled", resumed)
		})
	}
}
