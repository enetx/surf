package connrace

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/surf/profiles"
	"github.com/stretchr/testify/require"
)

func raceTestRequest(t *testing.T, ctx context.Context) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.invalid/", nil)
	require.NoError(t, err)
	return req
}

func TestConnectionRaceOneCanceledWaiterPreservesOther(t *testing.T) {
	quicReady := make(chan struct{})
	var quicCalls, tcpCalls atomic.Int32
	r := &Racer{
		policy: func(profiles.ConnectionRacingInfo) time.Duration { return 0 },
		quic: func(ctx context.Context, _ string) error {
			quicCalls.Add(1)
			select {
			case <-quicReady:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		},
		tcp: func(req *http.Request) (bool, error) {
			tcpCalls.Add(1)
			<-req.Context().Done()
			return false, context.Cause(req.Context())
		},
	}
	defer r.Close(false)
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { _, err := r.SelectProtocol(raceTestRequest(t, ctx), "example.invalid:443"); first <- err }()
	go func() {
		f, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443")
		if err == nil && f.Protocol != 3 {
			err = errors.New("wrong winner")
		}
		second <- err
	}()
	require.Eventually(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		o := r.origins["example.invalid:443"]
		return o != nil && o.flight != nil && o.flight.waiters == 2 && tcpCalls.Load() == 1
	}, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-first, context.Canceled)
	close(quicReady)
	require.NoError(t, <-second)
	require.EqualValues(t, 1, quicCalls.Load())
	require.EqualValues(t, 1, tcpCalls.Load())
}

func TestConnectionRaceFailureKeepsBothCausesAndBoundsHistory(t *testing.T) {
	qerr, terr := errors.New("quic failure"), errors.New("tcp failure")
	r := &Racer{
		policy: func(profiles.ConnectionRacingInfo) time.Duration { return time.Hour },
		quic:   func(context.Context, string) error { return qerr },
		tcp:    func(*http.Request) (bool, error) { return false, terr },
	}
	_, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443")
	require.ErrorIs(t, err, qerr)
	require.ErrorIs(t, err, terr)
	for i := range maxOrigins + 16 {
		_, err = r.SelectProtocol(raceTestRequest(t, t.Context()), fmt.Sprintf("host-%d.invalid:443", i))
		require.Error(t, err)
	}
	r.Close(false)
	require.LessOrEqual(t, len(r.origins), maxOrigins)
	require.Empty(t, r.flights)
	_, err = r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443")
	require.ErrorContains(t, err, "closed")
}

func TestConnectionRaceCloseStopsSelectedBackgroundHandshake(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	r := &Racer{
		policy: func(profiles.ConnectionRacingInfo) time.Duration { return 0 },
		quic: func(ctx context.Context, _ string) error {
			close(started)
			<-ctx.Done()
			close(stopped)
			return context.Cause(ctx)
		},
		tcp: func(*http.Request) (bool, error) { return false, nil },
	}
	f, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443")
	require.NoError(t, err)
	require.Equal(t, 2, f.Protocol)
	<-started
	r.Close(true)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("idle cleanup left background handshake running")
	}
	r.Close(false)
	require.Empty(t, r.flights)
}

func TestConnectionRaceAuthorityNormalization(t *testing.T) {
	for input, want := range map[string]string{"https://example.org/": "example.org:443", "https://example.org:8443/": "example.org:8443", "https://[::1]/": "[::1]:443", "https://bücher.example/": "xn--bcher-kva.example:443"} {
		req, err := http.NewRequest(http.MethodGet, input, nil)
		require.NoError(t, err)
		address, err := Address(req)
		require.NoError(t, err)
		require.Equal(t, want, address)
	}
	req := new(http.Request)
	req.URL = &url.URL{Scheme: "https"}
	_, err := Address(req)
	require.Error(t, err)
}
