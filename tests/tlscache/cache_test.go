package tlscache_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf/pkg/tlscache"
	chromequic "github.com/enetx/surf/profiles/chrome/quic"
	utls "github.com/enetx/utls"
	"github.com/stretchr/testify/require"
)

func ticketFactory(t *testing.T, now time.Time) func(string, uint16, time.Duration) *tls.ClientSessionState {
	t.Helper()
	// Start from an actual client session: SessionState.Bytes intentionally
	// distinguishes client and server state using private TLS fields.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ticket") }))
	defer server.Close()
	stored := &recordingCache{stored: make(chan *tls.ClientSessionState, 4)}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ClientSessionCache: stored}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get(server.URL)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	response.Body.Close()
	var seed *tls.ClientSessionState
	select {
	case seed = <-stored.stored:
	case <-time.After(5 * time.Second):
		t.Fatal("no client session")
	}
	_, seedState, err := seed.ResumptionState()
	require.NoError(t, err)
	seedBytes, err := seedState.Bytes()
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return func(id string, version uint16, lifetime time.Duration) *tls.ClientSessionState {
		parsed, err := utls.ParseSessionState(seedBytes)
		require.NoError(t, err)
		state, err := utls.NewResumptionState([]byte(id), parsed)
		require.NoError(t, err)
		state.SetVers(version)
		state.SetServerCertificates([]*x509.Certificate{cert})
		state.SetCreatedAt(uint64(now.Unix()))
		state.SetUseBy(uint64(now.Add(lifetime).Unix()))
		label, metadata, err := state.ResumptionState()
		require.NoError(t, err)
		data, err := metadata.Bytes()
		require.NoError(t, err)
		converted, err := tls.ParseSessionState(data)
		require.NoError(t, err)
		result, err := tls.NewResumptionState(label, converted)
		require.NoError(t, err)
		return result
	}
}

type recordingCache struct{ stored chan *tls.ClientSessionState }

func (c *recordingCache) Get(string) (*tls.ClientSessionState, bool) { return nil, false }
func (c *recordingCache) Put(_ string, state *tls.ClientSessionState) {
	if state != nil {
		c.stored <- state
	}
}

func label(t *testing.T, cache *tlscache.Cache, key string) string {
	t.Helper()
	state, ok := cache.Get(key)
	if !ok {
		return ""
	}
	data, _, err := state.ResumptionState()
	require.NoError(t, err)
	return string(data)
}

func TestNewestTwoTicketsAreConsumedOnce(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	newTicket := ticketFactory(t, now)
	cache := tlscache.New().TicketsPerKey(2).Clock(func() time.Time { return now }).Build().Unwrap()
	states := make(map[string]*tls.ClientSessionState)
	for _, id := range []string{"a", "b", "c"} {
		states[id] = newTicket(id, tls.VersionTLS13, time.Hour)
		cache.Put("server", states[id])
	}
	require.Equal(t, "c", label(t, cache, "server"))
	require.Equal(t, "b", label(t, cache, "server"))
	require.Empty(t, label(t, cache, "server"))
	cache.Put("server", states["c"])
	require.Empty(t, label(t, cache, "server"), "a consumed ticket cannot be resurrected")
	cache.Put("server", nil)
	cache.Put("server", states["c"])
	require.Equal(t, "c", label(t, cache, "server"), "an explicit reset releases consumed state")
}

func TestFirefoxExpiryOrderingAndOverflow(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	newTicket := ticketFactory(t, now)
	cache := tlscache.New().TicketsPerKey(10).Order(tlscache.EarliestExpiryFirst).Clock(func() time.Time { return now }).Build().Unwrap()
	for i := 1; i <= 12; i++ {
		cache.Put("server", newTicket(strconv.Itoa(i), tls.VersionTLS13, time.Duration(i)*time.Minute))
	}
	for i := 3; i <= 12; i++ {
		require.Equal(t, strconv.Itoa(i), label(t, cache, "server"))
	}
	require.Empty(t, label(t, cache, "server"))
	cache.Put("equal", newTicket("first", tls.VersionTLS13, time.Hour))
	cache.Put("equal", newTicket("second", tls.VersionTLS13, time.Hour))
	require.Equal(t, "second", label(t, cache, "equal"))
	require.Equal(t, "first", label(t, cache, "equal"))
}

func TestExpiryPoliciesAndLegacyReuse(t *testing.T) {
	for _, discard := range []bool{false, true} {
		t.Run(strconv.FormatBool(discard), func(t *testing.T) {
			now := time.Now().Truncate(time.Second)
			newTicket := ticketFactory(t, now)
			cache := tlscache.New().TicketsPerKey(2).DiscardOnExpiry(discard).Clock(func() time.Time { return now }).Build().Unwrap()
			cache.Put("server", newTicket("long", tls.VersionTLS13, time.Hour))
			cache.Put("server", newTicket("short", tls.VersionTLS13, time.Minute))
			now = now.Add(2 * time.Minute)
			if discard {
				require.Empty(t, label(t, cache, "server"))
			} else {
				require.Equal(t, "long", label(t, cache, "server"))
			}
		})
	}
	now := time.Now().Truncate(time.Second)
	newTicket := ticketFactory(t, now)
	for _, reuse := range []bool{false, true} {
		cache := tlscache.New().ReuseTLS12(reuse).Build().Unwrap()
		cache.Put("legacy", newTicket("tls12", tls.VersionTLS12, time.Hour))
		require.Equal(t, "tls12", label(t, cache, "legacy"))
		if reuse {
			require.Equal(t, "tls12", label(t, cache, "legacy"))
		} else {
			require.Empty(t, label(t, cache, "legacy"))
		}
	}
}

func TestCompatibilityIsolationEvictionAndCallbacks(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	newTicket := ticketFactory(t, now)
	group := "first"
	var cache *tlscache.Cache
	cache = tlscache.New().Capacity(2).TicketsPerKey(2).Group(func(*tls.ClientSessionState) string {
		// A callback may inspect another key without deadlocking.
		cache.Get("absent")
		return group
	}).Build().Unwrap()
	cache.Put("one", newTicket("old", tls.VersionTLS13, time.Hour))
	group = "second"
	cache.Put("one", newTicket("new", tls.VersionTLS13, time.Hour))
	require.Equal(t, "new", label(t, cache, "one"))
	require.Empty(t, label(t, cache, "one"))
	cache.Put("two", newTicket("two", tls.VersionTLS13, time.Hour))
	cache.Put("three", newTicket("three", tls.VersionTLS13, time.Hour))
	require.Empty(t, label(t, cache, "one"))
	require.Equal(t, "two", label(t, cache, "two"))
	cache.Clear()
	require.Empty(t, label(t, cache, "three"))
	cache.Put("bad", new(tls.ClientSessionState))
	require.Empty(t, label(t, cache, "bad"))
}

func TestConcurrentLookupDoesNotReuseOneTicket(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	newTicket := ticketFactory(t, now)
	cache := tlscache.New().Build().Unwrap()
	cache.Put("server", newTicket("one-use", tls.VersionTLS13, time.Hour))
	var hits atomic.Int32
	var workers sync.WaitGroup
	for range 100 {
		workers.Go(func() {
			if _, ok := cache.Get("server"); ok {
				hits.Add(1)
			}
		})
	}
	workers.Wait()
	require.EqualValues(t, 1, hits.Load())
}

func TestBuilderValidation(t *testing.T) {
	for _, builder := range []*tlscache.Builder{tlscache.New().Capacity(0), tlscache.New().TicketsPerKey(0), tlscache.New().Order(99)} {
		require.True(t, builder.Build().IsErr())
	}
}

func TestPeekAndEarlyDataRejectionPreserveRemainingPSKs(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	newTicket := ticketFactory(t, now)
	for _, clearEarly := range []bool{false, true} {
		cache := tlscache.New().TicketsPerKey(2).ClearEarlyDataOnReject(clearEarly).Build().Unwrap()
		for _, id := range []string{"first", "second"} {
			state := newTicket(id, tls.VersionTLS13, time.Hour)
			_, metadata, err := state.ResumptionState()
			require.NoError(t, err)
			metadata.EarlyData = true
			cache.Put("server", state)
		}
		peek, ok := cache.Peek("server")
		require.True(t, ok)
		_, metadata, err := peek.ResumptionState()
		require.NoError(t, err)
		require.True(t, metadata.EarlyData)
		require.Equal(t, "second", label(t, cache, "server"))
		cache.RejectEarlyData("server")
		pending, ok := cache.Peek("server")
		require.True(t, ok)
		_, metadata, err = pending.ResumptionState()
		require.NoError(t, err)
		require.Equal(t, !clearEarly, metadata.EarlyData)
		require.Equal(t, "first", label(t, cache, "server"))
		require.Empty(t, label(t, cache, "server"))
	}
}

// Chromium TCP pops one ticket before checking its lifetime. A newer expired
// ticket causes one cold connection; the older live ticket remains available.
func TestExpiredTicketCanFailOneLookupWithoutDiscardingOlderTicket(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	newTicket := ticketFactory(t, now)
	cache := tlscache.New().TicketsPerKey(2).SkipExpired(false).Clock(func() time.Time { return now }).Build().Unwrap()
	cache.Put("server", newTicket("older-live", tls.VersionTLS13, time.Hour))
	cache.Put("server", newTicket("newer-expired", tls.VersionTLS13, time.Minute))
	now = now.Add(2 * time.Minute)
	require.Empty(t, label(t, cache, "server"))
	require.Equal(t, "older-live", label(t, cache, "server"))
	require.Empty(t, label(t, cache, "server"))
}

func TestChromeQUICProfileInvalidatesChangedConnectionContext(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	newTicket := ticketFactory(t, now)
	settings := tlscache.New()
	chromequic.ConfigureSessionCache(settings)
	cache := settings.Build().Unwrap()
	put := func(label, cid string, rtt uint64) {
		state := newTicket(label, tls.VersionTLS13, time.Hour)
		_, metadata, err := state.ResumptionState()
		require.NoError(t, err)
		extra := binary.BigEndian.AppendUint32(append([]byte("quic-go1"), 7), uint32(quic.Version1))
		extra = quicvarint.Append(extra, rtt)
		extra = quicvarint.Append(extra, uint64(len(cid)))
		extra = append(extra, cid...)
		metadata.Extra = [][]byte{extra}
		cache.Put("server", state)
	}
	put("older", "connection-one", uint64(time.Millisecond))
	put("newer", "connection-one", uint64(2*time.Millisecond))
	require.Equal(t, "newer", label(t, cache, "server"))
	require.Equal(t, "older", label(t, cache, "server"), "RTT alone must not invalidate tickets")
	put("old-context", "connection-one", 0)
	put("new-context", "connection-two", 0)
	require.Equal(t, "new-context", label(t, cache, "server"))
	require.Empty(t, label(t, cache, "server"))
}

func TestChromeQUICProfileGroupsRememberedHTTP3Settings(t *testing.T) {
	newTicket := ticketFactory(t, time.Now())
	for _, tc := range []struct {
		name         string
		old, current [][2]uint64
		same         bool
	}{
		{"identical", [][2]uint64{{1, 4096}, {7, 16}}, [][2]uint64{{1, 4096}, {7, 16}}, true},
		{"reordered", [][2]uint64{{1, 4096}, {7, 16}}, [][2]uint64{{7, 16}, {1, 4096}}, true},
		{"capacity", [][2]uint64{{1, 4096}}, [][2]uint64{{1, 8192}}, false},
		{"blocked streams", [][2]uint64{{7, 16}}, [][2]uint64{{7, 32}}, false},
		{"header limit", [][2]uint64{{6, 4096}}, [][2]uint64{{6, 8192}}, false},
		{"explicit zero", nil, [][2]uint64{{6, 0}}, false},
		{"datagrams", nil, [][2]uint64{{51, 1}}, false},
		{"connect", nil, [][2]uint64{{8, 1}}, false},
		{"extension", [][2]uint64{{1337, 1}}, [][2]uint64{{1337, 2}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := tlscache.New()
			chromequic.ConfigureSessionCache(settings)
			cache := settings.Build().Unwrap()
			put := func(name string, fields [][2]uint64) {
				state := newTicket(name, tls.VersionTLS13, time.Hour)
				_, metadata, err := state.ResumptionState()
				require.NoError(t, err)
				transport := binary.BigEndian.AppendUint32(append([]byte("quic-go1"), 7), uint32(quic.Version1))
				transport = quicvarint.Append(transport, 0) // RTT
				transport = quicvarint.Append(transport, 4)
				transport = append(transport, "same"...)
				var payload []byte
				for _, field := range fields {
					payload = quicvarint.Append(quicvarint.Append(payload, field[0]), field[1])
				}
				application := quicvarint.Append([]byte("quic-go h3 peer settings v1\x00"), 4)
				application = append(quicvarint.Append(application, uint64(len(payload))), payload...)
				metadata.Extra = [][]byte{transport, application}
				cache.Put("server", state)
			}
			put("older", tc.old)
			put("newer", tc.current)
			require.Equal(t, "newer", label(t, cache, "server"))
			if tc.same {
				require.Equal(t, "older", label(t, cache, "server"))
			} else {
				require.Empty(t, label(t, cache, "server"))
			}
		})
	}
}
