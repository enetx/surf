package h3transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/internal/quictls"
	"github.com/stretchr/testify/require"
)

type versionCaptureCache struct {
	tls.ClientSessionCache
	stored  chan *tls.ClientSessionState
	consume bool
}

func (c *versionCaptureCache) Put(key string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, state)
	if state != nil {
		select {
		case c.stored <- state:
		default:
		}
	}
}

func (c *versionCaptureCache) Get(key string) (*tls.ClientSessionState, bool) {
	state, ok := c.ClientSessionCache.Get(key)
	if c.consume {
		c.ClientSessionCache.Put(key, nil)
	}
	return state, ok
}

func realVersionTicket(t *testing.T) *tls.ClientSessionState {
	t.Helper()
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsConfig := cert.TLS.Clone()
	cert.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	server := &http3.Server{TLSConfig: tlsConfig, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version2}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ticket") })}
	defer server.Close()
	go server.Serve(udp)
	cache := &versionCaptureCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), stored: make(chan *tls.ClientSessionState, 4)}
	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version2}}}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+udp.LocalAddr().String(), nil)
	require.NoError(t, err)
	response, err := transport.RoundTrip(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	response.Body.Close()
	select {
	case state := <-cache.stored:
		return state
	case <-ctx.Done():
		t.Fatal("no real v2 session ticket")
	}
	return nil
}

func TestSessionVersionSelectsLiveTicketAndPreservesConfiguration(t *testing.T) {
	state := realVersionTicket(t)
	h := &sessionVersions{}
	cache := &versionCaptureCache{ClientSessionCache: tls.NewLRUClientSessionCache(8), consume: true}
	baseTLS := &tls.Config{ClientSessionCache: cache}
	baseQUIC := &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}}
	first, config := h.prepare("ORIGIN:443", baseTLS, baseQUIC)
	require.Same(t, baseQUIC, config)
	first.ClientSessionCache.Put("opaque TLS cache key", state)
	prepared, selected := h.prepare("origin:443", baseTLS, baseQUIC)
	require.Equal(t, []quic.Version{quic.Version2, quic.Version1}, selected.Versions)
	require.Equal(t, []quic.Version{quic.Version1, quic.Version2}, baseQUIC.Versions)
	require.Same(t, cache, baseTLS.ClientSessionCache)
	chosen, ok := prepared.ClientSessionCache.Get("opaque TLS cache key")
	require.True(t, ok, "selection must not consume a single-use ticket twice")
	require.Same(t, state, chosen)
	_, ok = prepared.ClientSessionCache.Get("opaque TLS cache key")
	require.False(t, ok)
	_, missing := h.prepare("origin:443", baseTLS, baseQUIC)
	require.Same(t, baseQUIC, missing, "an evicted/consumed ticket cannot select a version")
}

func TestSessionVersionValidationIsolationAndLifetime(t *testing.T) {
	state := realVersionTicket(t)
	from, until, ok := quictls.SessionLifetime(state)
	require.True(t, ok)
	for _, mode := range []string{"other-origin", "other-port", "expired", "not-yet-valid", "disabled-version", "ticket-disabled", "overwritten", "closed"} {
		t.Run(mode, func(t *testing.T) {
			h := &sessionVersions{}
			cache := tls.NewLRUClientSessionCache(8)
			baseTLS := &tls.Config{ClientSessionCache: cache}
			baseQUIC := &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}}
			prepared, _ := h.prepare("origin:443", baseTLS, baseQUIC)
			prepared.ClientSessionCache.Put("key", state)
			origin := "origin:443"
			switch mode {
			case "other-origin":
				origin = "other:443"
			case "other-port":
				origin = "origin:8443"
			case "expired":
				baseTLS.Time = func() time.Time { return until.Add(time.Second) }
			case "not-yet-valid":
				baseTLS.Time = func() time.Time { return from.Add(-time.Second) }
			case "disabled-version":
				baseQUIC.Versions = []quic.Version{quic.Version1}
			case "ticket-disabled":
				baseTLS.SessionTicketsDisabled = true
			case "overwritten":
				_, session, err := state.ResumptionState()
				require.NoError(t, err)
				other, err := tls.NewResumptionState([]byte("another origin's ticket"), session)
				require.NoError(t, err)
				cache.Put("key", other)
			case "closed":
				h.close()
			}
			_, config := h.prepare(origin, baseTLS, baseQUIC)
			require.Same(t, baseQUIC, config)
			require.Equal(t, quic.Version1, config.Versions[0])
		})
	}
}

func TestSessionVersionConcurrentBoundedHistoryAndShutdown(t *testing.T) {
	state := realVersionTicket(t)
	h := &sessionVersions{}
	base := &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(512)}
	var group sync.WaitGroup
	for i := range 300 {
		group.Go(func() {
			origin := "host-" + strconv.Itoa(i) + ":443"
			prepared, _ := h.prepare(origin, base, nil)
			prepared.ClientSessionCache.Put(origin, state)
		})
	}
	group.Wait()
	require.Len(t, h.entries, 256)
	prepared, _ := h.prepare("last:443", base, nil)
	prepared.ClientSessionCache.Put("last", state)
	prepared.ClientSessionCache.Put("last", nil)
	_, exists := h.entries["last:443"]
	require.False(t, exists)
	h.close()
	prepared.ClientSessionCache.Put("late", state)
	require.Empty(t, h.entries)
}
