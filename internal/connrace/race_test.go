package connrace

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/surf/profiles"
	"github.com/stretchr/testify/require"
)

func raceTestRequest(t *testing.T, ctx context.Context) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.invalid/", nil)
	require.NoError(t, err)
	return req
}

func TestConnectionRaceOldConfirmedConnectionPreservesLaterFailure(t *testing.T) {
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	serverTLS := cert.TLS.Clone()
	cert.Close()
	serverTLS.NextProtos = []string{"race-test"}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: serverTLS.NextProtos}, nil)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "test complete")
	require.True(t, conn.ConnectionState().TLS.HandshakeComplete)

	laterFailure := errors.New("a later QUIC attempt failed")
	var observed profiles.ConnectionRacingInfo
	var usedEarly bool
	r := New(func(info profiles.ConnectionRacingInfo) time.Duration {
		observed = info
		return time.Hour
	}, func(_ context.Context, _ string, early bool) error {
		usedEarly = early
		return nil
	}, func(*http.Request) (bool, error) { return false, errors.New("unexpected TCP attempt") })
	defer r.Close(false)
	r.origins = map[string]*originState{"example.invalid:443": {conn: conn, info: profiles.ConnectionRacingInfo{LastQUICError: laterFailure}}}
	r.flights = make(map[*flight]struct{})
	_, err = r.SelectProtocol(raceTestRequest(t, ctx), "example.invalid:443", true)
	require.NoError(t, err)
	require.ErrorIs(t, observed.LastQUICError, laterFailure)
	require.False(t, usedEarly, "recent failures require a confirmed handshake")
}

func TestConnectionRaceOneCanceledWaiterPreservesOther(t *testing.T) {
	quicReady := make(chan struct{})
	var quicCalls, tcpCalls atomic.Int32
	r := &Racer{
		policy: func(profiles.ConnectionRacingInfo) time.Duration { return 0 },
		quic: func(ctx context.Context, _ string, _ bool) error {
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
	go func() {
		_, err := r.SelectProtocol(raceTestRequest(t, ctx), "example.invalid:443", false)
		first <- err
	}()
	go func() {
		f, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443", false)
		if err == nil && f.Protocol != 3 {
			err = errors.New("wrong winner")
		}
		second <- err
	}()
	require.Eventually(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		o := r.origins["example.invalid:443"]
		return o != nil && o.flights[0] != nil && o.flights[0].waiters == 2 && tcpCalls.Load() == 1
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
		quic:   func(context.Context, string, bool) error { return qerr },
		tcp:    func(*http.Request) (bool, error) { return false, terr },
	}
	_, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443", false)
	require.ErrorIs(t, err, qerr)
	require.ErrorIs(t, err, terr)
	for i := range maxOrigins + 16 {
		_, err = r.SelectProtocol(raceTestRequest(t, t.Context()), fmt.Sprintf("host-%d.invalid:443", i), false)
		require.Error(t, err)
	}
	r.Close(false)
	require.LessOrEqual(t, len(r.origins), maxOrigins)
	require.Empty(t, r.flights)
	_, err = r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443", false)
	require.ErrorContains(t, err, "closed")
}

func TestConnectionRaceCloseStopsSelectedBackgroundHandshake(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	r := &Racer{
		policy: func(profiles.ConnectionRacingInfo) time.Duration { return 0 },
		quic: func(ctx context.Context, _ string, _ bool) error {
			close(started)
			<-ctx.Done()
			close(stopped)
			return context.Cause(ctx)
		},
		tcp: func(*http.Request) (bool, error) { return false, nil },
	}
	f, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443", false)
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

func TestConnectionRaceEarlyWaiterDoesNotCommitUnsafeWaiter(t *testing.T) {
	confirmed, started := make(chan struct{}), make(chan struct{})
	r := &Racer{
		policy: func(profiles.ConnectionRacingInfo) time.Duration { return time.Hour },
		quic: func(ctx context.Context, _ string, early bool) error {
			if early {
				return nil
			}
			close(started)
			select {
			case <-confirmed:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		},
		tcp: func(*http.Request) (bool, error) { return false, nil },
	}
	defer r.Close(false)
	unsafe := make(chan error, 1)
	go func() {
		_, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443", false)
		unsafe <- err
	}()
	<-started
	selected, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "example.invalid:443", true)
	require.NoError(t, err)
	require.Equal(t, 3, selected.Protocol)
	select {
	case <-unsafe:
		t.Fatal("early readiness released a caller requiring a confirmed connection")
	default:
	}
	close(confirmed)
	require.NoError(t, <-unsafe)
}
