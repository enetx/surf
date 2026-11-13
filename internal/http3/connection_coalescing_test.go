package h3transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestAdvertisedOriginCanonicalization(t *testing.T) {
	for raw, want := range map[string]string{
		"https://EXAMPLE.COM":        "https://example.com:443",
		"https://example.com:0443":   "https://example.com:443",
		"https://[2001:db8::1]:8443": "https://[2001:db8::1]:8443",
		"http://example.com":         "http://example.com:80",
		"https://example.com/path":   "",
		"https://example.com/":       "",
		"https://example.com:65536":  "",
		"https://":                   "",
		"null":                       "",
		"https://exa mple.com":       "",
	} {
		t.Run(raw, func(t *testing.T) {
			origin, valid := parseAdvertisedOrigin(raw)
			require.Equal(t, want != "", valid)
			if valid {
				require.Equal(t, want, origin)
			}
		})
	}
}

func TestCoalescingResolutionIsSharedWithinOneAttemptOnly(t *testing.T) {
	c := &connectionCoalescer{transport: &Transport{}}
	ctx := c.prepareContext(t.Context(), "b.test:443")
	var calls atomic.Int32
	failure := errors.New("first lookup failed")
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		if calls.Add(1) == 1 {
			return nil, failure
		}
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	var group sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			_, err := coalescingLookup(ctx, "b.test", lookup)
			results <- err
		})
	}
	group.Wait()
	close(results)
	for err := range results {
		require.ErrorIs(t, err, failure)
	}
	require.EqualValues(t, 1, calls.Load())
	// A later request can recover; failures do not become persistent DNS state.
	next := c.prepareContext(t.Context(), "b.test:443")
	addresses, err := coalescingLookup(next, "b.test", lookup)
	require.NoError(t, err)
	require.Len(t, addresses, 1)
	require.EqualValues(t, 2, calls.Load())
}

func TestOriginFrameDoesNotPublishPartialOrTruncatedState(t *testing.T) {
	entry := []byte("https://b.test")
	validPrefix := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	validPrefix = append(validPrefix, entry...)
	for _, tail := range [][]byte{{1}, {0, 9, 'b'}, {0, 4}} {
		payload := append(bytes.Clone(validPrefix), tail...)
		c := &connectionCoalescer{originLimit: 20, peers: make(map[*quic.Conn]*coalescingPeer)}
		err := c.readOriginFrame(nil, bytes.NewReader(payload), uint64(len(payload)))
		require.Error(t, err)
		require.Empty(t, c.peers, "an incomplete frame cannot publish its earlier entries")
	}
	for _, missing := range []uint64{1, 2, 1000} {
		c := &connectionCoalescer{originLimit: 20, peers: make(map[*quic.Conn]*coalescingPeer)}
		err := c.readOriginFrame(nil, bytes.NewReader(validPrefix), uint64(len(validPrefix))+missing)
		require.Error(t, err, "an early EOF must not look like the declared end of the frame")
		require.Empty(t, c.peers)
	}
}

func TestConnectionOptionsUseFourByteTagBoundaries(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"NOIP", true}, {"ORIGNOIP", true}, {"", false}, {"ORIG", false},
		{"xNOIPxxx", false}, {"NOIPx", false}, {"NOIPNOIP", true},
	} {
		require.Equal(t, tc.want, hasConnectionOption([]byte(tc.value), "NOIP"), tc.value)
	}
}
