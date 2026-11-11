package surf_test

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type h3QPACKCapture struct {
	typ    uint64
	id     quic.StreamID
	stream *quic.ReceiveStream
	reader quicvarint.Reader
}

func nextSurfQPACKStream(t *testing.T, peer *h3Peer) h3QPACKCapture {
	t.Helper()
	select {
	case stream := <-peer.qpackStreams:
		return stream
	case err := <-peer.errors:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("missing QPACK stream")
	}
	return h3QPACKCapture{}
}

func readSurfQPACKCapacity(t *testing.T, stream h3QPACKCapture) uint64 {
	t.Helper()
	stream.stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	first, err := stream.reader.ReadByte()
	require.NoError(t, err)
	require.EqualValues(t, 0x20, first&0xe0)
	value := uint64(first & 31)
	if value < 31 {
		return value
	}
	for shift := uint(0); shift < 63; shift += 7 {
		b, err := stream.reader.ReadByte()
		require.NoError(t, err)
		value += uint64(b&127) << shift
		if b < 128 {
			return value
		}
	}
	t.Fatal("QPACK capacity integer overflow")
	return 0
}

func TestHTTP3QPACKFluentConfigurationOnWire(t *testing.T) {
	for _, eager := range []bool{false, true} {
		t.Run(fmt.Sprint(eager), func(t *testing.T) {
			capacity := uint64(4096)
			first, second := newH3PeerWithQPACK(t, &capacity), newH3PeerWithQPACK(t, &capacity)
			order := []surf.QPACKStreamType{surf.QPACKDecoderStream, surf.QPACKEncoderStream}
			builder := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3()
			h3 := builder.HTTP3Settings().QpackStreamOrder(order...).QpackEagerStreamTypes(eager).
				QpackEncoderTableCapacity(512).QpackEncoderCapacityTiming(surf.QPACKCapacityOnSettings)
			order[0] = 99 // Slice arguments must already have been copied.
			client := h3.Set().Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			// A completed client retains its settings even for connections to new origins.
			builder.HTTP3Settings().QpackStreamOrder(surf.QPACKEncoderStream).
				QpackEagerStreamTypes(!eager).QpackEncoderTableCapacity(1)
			for _, peer := range []*h3Peer{first, second} {
				capture := peer.request(t, client)
				require.Contains(t, capture.settings, h3Setting{1, 65536}, "receive capacity is independent of encoder capacity")
				count := 1
				if eager {
					count = 2
				}
				seen := make(map[uint64]bool)
				for range count {
					stream := nextSurfQPACKStream(t, peer)
					require.False(t, seen[stream.typ], "duplicate QPACK stream")
					seen[stream.typ] = true
					if stream.typ == 2 {
						require.EqualValues(t, 10, stream.id)
						require.EqualValues(t, 512, readSurfQPACKCapacity(t, stream))
					} else {
						require.EqualValues(t, 3, stream.typ)
						require.EqualValues(t, 6, stream.id)
					}
				}
				require.True(t, seen[2])
				if !eager {
					select {
					case stream := <-peer.qpackStreams:
						t.Fatalf("lazy decoder unexpectedly wrote type %d", stream.typ)
					case <-time.After(25 * time.Millisecond):
					}
				}
			}
		})
	}
}

func TestHTTP3QPACKFluentValidation(t *testing.T) {
	for name, configure := range map[string]func(*surf.HTTP3Settings){
		"never-index name":  func(h *surf.HTTP3Settings) { h.QpackNeverIndex("bad name") },
		"duplicate":         func(h *surf.HTTP3Settings) { h.QpackStreamOrder(surf.QPACKEncoderStream, surf.QPACKEncoderStream) },
		"type":              func(h *surf.HTTP3Settings) { h.QpackStreamOrder(0) },
		"capacity":          func(h *surf.HTTP3Settings) { h.QpackEncoderTableCapacity(1 << 62) },
		"timing":            func(h *surf.HTTP3Settings) { h.QpackEncoderCapacityTiming(99) },
		"huffman":           func(h *surf.HTTP3Settings) { h.QpackHuffman(99) },
		"indexing":          func(h *surf.HTTP3Settings) { h.QpackIndexing(99) },
		"draining negative": func(h *surf.HTTP3Settings) { h.QpackDrainingFraction(-.1) },
		"draining excess":   func(h *surf.HTTP3Settings) { h.QpackDrainingFraction(1.1) },
		"draining NaN":      func(h *surf.HTTP3Settings) { h.QpackDrainingFraction(math.NaN()) },
		"tracking limit":    func(h *surf.HTTP3Settings) { h.QpackMaxTrackedSections(1 << 62) },
	} {
		t.Run(name, func(t *testing.T) {
			h := surf.NewClient().Builder().ForceHTTP3().HTTP3Settings()
			configure(h)
			result := h.Set().Build()
			require.True(t, result.IsErr())
			require.ErrorContains(t, result.Err(), "QPACK")
		})
	}
}

func TestChromeQPACKOmittedAndExplicitZeroCapacity(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			var peer *h3Peer
			if explicit {
				zero := uint64(0)
				peer = newH3PeerWithQPACK(t, &zero)
			} else {
				peer = newH3Peer(t)
			}
			client := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP3().Proxy("").Build().Unwrap()
			defer client.Close()
			peer.request(t, client)
			peer.request(t, client)
			if explicit {
				stream := nextSurfQPACKStream(t, peer)
				require.EqualValues(t, 2, stream.typ)
				require.Zero(t, readSurfQPACKCapacity(t, stream))
			} else {
				select {
				case stream := <-peer.qpackStreams:
					t.Fatalf("omitted capacity opened QPACK stream %d", stream.typ)
				case err := <-peer.errors:
					t.Fatal(err)
				case <-time.After(30 * time.Millisecond):
				}
			}
		})
	}
}
