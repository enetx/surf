package connrace

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/surf/profiles"
	"github.com/stretchr/testify/require"
)

func TestConnectionRaceObservedConfirmationEstablishesHistoryAcrossOrigins(t *testing.T) {
	conn := confirmedRaceConnection(t)
	observed := make(chan profiles.ConnectionRacingInfo, 1)
	r := New(func(info profiles.ConnectionRacingInfo) time.Duration {
		observed <- info
		return time.Hour
	}, func(context.Context, string, bool) error { return nil },
		func(*http.Request) (bool, error) { return false, nil })
	defer r.Close(false)

	// An early-ready preparation can finish before TLS. Its retained connection
	// becomes evidence for a different origin after confirmation, without another
	// request to the original origin or an origin-level success flag.
	r.origins = map[string]*originState{"early.invalid:443": {}}
	r.flights = make(map[*flight]struct{})
	r.ObserveQUIC("early.invalid:443", conn)
	_, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "other.invalid:443", false)
	require.NoError(t, err)
	info := <-observed
	require.True(t, info.QUICWorkedInClient)
	require.False(t, info.QUICWorked)
	require.Zero(t, info.SmoothedRTT)
}

func TestConnectionRaceClientHistoryKeepsOriginFailuresAndRTTSeparate(t *testing.T) {
	failure := errors.New("QUIC unavailable for this origin")
	observations := make(chan profiles.ConnectionRacingInfo, 16)
	fail := false
	r := New(func(info profiles.ConnectionRacingInfo) time.Duration {
		observations <- info
		return time.Hour
	}, func(context.Context, string, bool) error {
		if fail {
			return failure
		}
		return nil
	}, func(*http.Request) (bool, error) { return false, nil })
	defer r.Close(false)

	selectOrigin := func(address string) profiles.ConnectionRacingInfo {
		t.Helper()
		_, err := r.SelectProtocol(raceTestRequest(t, t.Context()), address, false)
		require.NoError(t, err)
		// Wait for the previous preparation to release its flight before the
		// next request, rather than accidentally reusing a selected TCP flight.
		r.wg.Wait()
		return <-observations
	}

	cold := selectOrigin("first.invalid:443")
	require.False(t, cold.QUICWorked)
	require.False(t, cold.QUICWorkedInClient)

	warm := selectOrigin("first.invalid:443")
	require.True(t, warm.QUICWorked)
	require.True(t, warm.QUICWorkedInClient)

	other := selectOrigin("other.invalid:443")
	require.False(t, other.QUICWorked)
	require.True(t, other.QUICWorkedInClient)
	require.Zero(t, other.SmoothedRTT, "another origin's RTT must not be inherited")
	require.Nil(t, other.LastQUICError)

	fail = true
	selectOrigin("broken.invalid:443")
	broken := selectOrigin("broken.invalid:443")
	require.False(t, broken.QUICWorked)
	require.True(t, broken.QUICWorkedInClient)
	require.ErrorIs(t, broken.LastQUICError, failure)

	fail = false
	selectOrigin("elsewhere.invalid:443")
	stillBroken := selectOrigin("broken.invalid:443")
	require.ErrorIs(t, stillBroken.LastQUICError, failure,
		"success elsewhere cannot clear this origin's later failure")
	recovered := selectOrigin("broken.invalid:443")
	require.True(t, recovered.QUICWorked)
	require.True(t, recovered.QUICWorkedInClient)
	require.Nil(t, recovered.LastQUICError)

	r.Close(true)
	// Origin entries may be evicted by the bounded history. Session-wide
	// support survives both origin eviction and ordinary idle cleanup.
	r.mu.Lock()
	clear(r.origins)
	r.mu.Unlock()
	afterCleanup := selectOrigin("new.invalid:443")
	require.False(t, afterCleanup.QUICWorked)
	require.True(t, afterCleanup.QUICWorkedInClient)
}

func TestConnectionRaceUnconfirmedEarlySuccessDoesNotEstablishClientHistory(t *testing.T) {
	observations := make(chan profiles.ConnectionRacingInfo, 3)
	r := New(func(info profiles.ConnectionRacingInfo) time.Duration {
		observations <- info
		return time.Hour
	}, func(context.Context, string, bool) error { return nil },
		func(*http.Request) (bool, error) { return false, nil })
	defer r.Close(false)

	_, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "early.invalid:443", true)
	require.NoError(t, err)
	r.wg.Wait()
	require.False(t, (<-observations).QUICWorkedInClient)

	_, err = r.SelectProtocol(raceTestRequest(t, t.Context()), "other.invalid:443", false)
	require.NoError(t, err)
	r.wg.Wait()
	require.False(t, (<-observations).QUICWorkedInClient,
		"early readiness alone must not count as a successful handshake")

	_, err = r.SelectProtocol(raceTestRequest(t, t.Context()), "third.invalid:443", false)
	require.NoError(t, err)
	require.True(t, (<-observations).QUICWorkedInClient)
}

func TestConnectionRaceTCPWinnerCanEstablishClientHistoryInBackground(t *testing.T) {
	confirmed := make(chan struct{})
	r := New(func(profiles.ConnectionRacingInfo) time.Duration { return 0 },
		func(ctx context.Context, _ string, _ bool) error {
			select {
			case <-confirmed:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}, func(*http.Request) (bool, error) { return false, nil })
	defer r.Close(false)

	result, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "first.invalid:443", false)
	require.NoError(t, err)
	require.Equal(t, 2, result.Protocol)
	r.mu.Lock()
	worked := r.quicWorked
	r.mu.Unlock()
	require.False(t, worked)

	close(confirmed)
	r.wg.Wait()
	r.mu.Lock()
	worked = r.quicWorked
	r.mu.Unlock()
	require.True(t, worked)
}

func TestConnectionRaceFailureAndCancellationDoNotEstablishClientHistory(t *testing.T) {
	for _, failure := range []error{errors.New("QUIC failed"), context.Canceled, context.DeadlineExceeded} {
		t.Run(failure.Error(), func(t *testing.T) {
			r := New(func(profiles.ConnectionRacingInfo) time.Duration { return time.Hour },
				func(context.Context, string, bool) error { return failure },
				func(*http.Request) (bool, error) { return false, nil })
			defer r.Close(false)

			_, err := r.SelectProtocol(raceTestRequest(t, t.Context()), "first.invalid:443", false)
			require.NoError(t, err)
			r.wg.Wait()
			require.False(t, r.quicWorked)
		})
	}
}
