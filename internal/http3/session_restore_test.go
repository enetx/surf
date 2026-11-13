package h3transport

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf/pkg/tlscache"
	"github.com/stretchr/testify/require"
)

func ticketWithMetadata(t *testing.T, base *tls.ClientSessionState, label string, rtt time.Duration) *tls.ClientSessionState {
	t.Helper()
	_, state, err := base.ResumptionState()
	require.NoError(t, err)
	data, err := state.Bytes()
	require.NoError(t, err)
	clone, err := tls.ParseSessionState(data)
	require.NoError(t, err)
	extra := binary.BigEndian.AppendUint32(append([]byte("quic-go1"), 7), uint32(quic.Version2))
	extra = quicvarint.Append(extra, uint64(rtt))
	extra = append(extra, 3, 'c', 'i', 'd')
	for i, old := range clone.Extra {
		if bytes.HasPrefix(old, []byte("quic-go1")) {
			clone.Extra[i] = extra
		}
	}
	result, err := tls.NewResumptionState([]byte(label), clone)
	require.NoError(t, err)
	return result
}

func TestSessionQueueFallbackAndRTTRestoration(t *testing.T) {
	base := realVersionTicket(t)
	queue := tlscache.New().TicketsPerKey(10).Order(tlscache.EarliestExpiryFirst).Build().Unwrap()
	h := &sessionVersions{restoreVersion: true, rttPrecision: time.Millisecond}
	config := &tls.Config{ClientSessionCache: queue}
	original := &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}, ClientHandshake: &quic.ClientHandshake{InitialRTT: 100 * time.Millisecond}}
	store, _ := h.prepare("origin:443", config, original)
	one := ticketWithMetadata(t, base, "older", 21*time.Millisecond+900*time.Microsecond)
	two := ticketWithMetadata(t, base, "newer", 37*time.Millisecond+999*time.Microsecond)
	store.ClientSessionCache.Put("opaque key", one)
	store.ClientSessionCache.Put("opaque key", two)
	for _, want := range []struct {
		label    string
		estimate time.Duration
	}{{"newer", 37 * time.Millisecond}, {"older", 21 * time.Millisecond}} {
		prepared, selected := h.prepare("origin:443", config, original)
		require.Equal(t, quic.Version2, selected.Versions[0])
		require.Equal(t, want.estimate, selected.ClientHandshake.InitialRTT)
		state, ok := prepared.ClientSessionCache.Get("opaque key")
		require.True(t, ok)
		identity, _, err := state.ResumptionState()
		require.NoError(t, err)
		require.Equal(t, want.label, string(identity))
	}
	_, cold := h.prepare("origin:443", config, original)
	require.Same(t, original, cold)
	require.Equal(t, []quic.Version{quic.Version1, quic.Version2}, original.Versions)
	require.Equal(t, 100*time.Millisecond, original.ClientHandshake.InitialRTT)
}

func TestSessionRTTPolicyDoesNotFabricateOrChangeDisallowedVersion(t *testing.T) {
	base := realVersionTicket(t)
	for _, mode := range []string{"disabled", "below-granularity", "rtt-only", "wrong-version"} {
		t.Run(mode, func(t *testing.T) {
			queue := tlscache.New().Build().Unwrap()
			h := &sessionVersions{restoreVersion: true, rttPrecision: time.Millisecond}
			config := &tls.Config{ClientSessionCache: queue}
			original := &quic.Config{Versions: []quic.Version{quic.Version2, quic.Version1}, ClientHandshake: &quic.ClientHandshake{InitialRTT: 100 * time.Millisecond}}
			rtt := 31 * time.Millisecond
			switch mode {
			case "disabled":
				h.rttPrecision = 0
			case "below-granularity":
				rtt = 500 * time.Microsecond
			case "rtt-only":
				h.restoreVersion = false
			case "wrong-version":
				h.restoreVersion = false
				original.Versions = []quic.Version{quic.Version1, quic.Version2}
			}
			store, _ := h.prepare("origin:443", config, original)
			store.ClientSessionCache.Put("key", ticketWithMetadata(t, base, "ticket", rtt))
			_, selected := h.prepare("origin:443", config, original)
			if mode == "rtt-only" {
				require.Equal(t, 31*time.Millisecond, selected.ClientHandshake.InitialRTT)
			} else {
				require.Equal(t, 100*time.Millisecond, selected.ClientHandshake.InitialRTT)
			}
			require.Equal(t, original.Versions[0], selected.Versions[0])
		})
	}
}

type refreshingSessionCache struct {
	tls.ClientSessionCache
	beforeGet func()
}

func (c *refreshingSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	if refresh := c.beforeGet; refresh != nil {
		c.beforeGet = nil
		refresh()
	}
	return c.ClientSessionCache.Get(key)
}

func TestSessionVersionKeepsTicketPublishedDuringLookup(t *testing.T) {
	base := realVersionTicket(t)
	cache := &refreshingSessionCache{ClientSessionCache: tlscache.New().Build().Unwrap()}
	h := &sessionVersions{restoreVersion: true, rttPrecision: time.Millisecond}
	config := &tls.Config{ClientSessionCache: cache}
	original := &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}}
	store, _ := h.prepare("origin:443", config, original)
	store.ClientSessionCache.Put("key", ticketWithMetadata(t, base, "old", time.Millisecond))
	fresh := ticketWithMetadata(t, base, "fresh", 29*time.Millisecond)
	// A post-handshake ticket can arrive after prepare snapshots the key list
	// but before the application's single-use cache selects its next ticket.
	cache.beforeGet = func() { store.ClientSessionCache.Put("key", fresh) }
	prepared, selected := h.prepare("origin:443", config, original)
	require.Equal(t, quic.Version2, selected.Versions[0])
	require.Equal(t, 29*time.Millisecond, selected.ClientHandshake.InitialRTT)
	state, ok := prepared.ClientSessionCache.Get("key")
	require.True(t, ok, "a newly published ticket must reach TLS instead of being discarded")
	require.Same(t, fresh, state)
	_, ok = prepared.ClientSessionCache.Get("key")
	require.False(t, ok, "selection must still consume the ticket exactly once")
}
