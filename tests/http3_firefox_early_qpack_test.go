package surf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

// This reference comes from accepted native early GETs, decoded independently
// with pylsqpack. Exercise the public profile and ordered headers over real
// resumed TLS/QUIC connections; a self-round-trip would miss encoding drift.
// Packet grouping is deliberately separate from byte and FIN conformance.
func TestFirefoxEarlyDynamicQPACKMatchesNative(t *testing.T) {
	data, err := os.ReadFile("testdata/wire/early_packing/firefox_160/dynamic_qpack.json")
	require.NoError(t, err)

	var fixture struct {
		Capacity uint64 `json:"peer_qpack_capacity"`
		Blocked  uint64 `json:"peer_qpack_blocked_streams"`
		Requests []struct {
			Request string      `json:"request_stream_hex"`
			Encoder string      `json:"encoder_stream_hex"`
			Fin     bool        `json:"fin"`
			Fields  [][2]string `json:"ordered_fields"`
		} `json:"requests"`
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.Len(t, fixture.Requests, 2)
	require.Positive(t, fixture.Capacity)
	require.Positive(t, fixture.Blocked)

	// The resumed server cannot finish its handshake until that connection has
	// actually emitted stream zero in 0-RTT. One signal per connection also
	// proves that neither a stale notification nor scheduler timing passes it.
	earlySent := make(chan struct{}, len(fixture.Requests))
	roots := x509.NewCertPool()
	var handshakes atomic.Int32
	peer := startH3PeerWithOptions(
		t,
		&fixture.Capacity,
		nil,
		nil,
		true,
		func(p *h3Peer, config *tls.Config) {
			p.qpackBlocked, p.rawQPACK = fixture.Blocked, true
			cert, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
			require.NoError(t, err)
			roots.AddCert(cert)

			config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				if handshakes.Add(1) == 1 {
					return nil, nil
				}

				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()

				select {
				case <-earlySent:
					return nil, nil
				case <-timer.C:
					return nil, errors.New("no native-equivalent early request")
				case <-info.Context().Done():
					return nil, info.Context().Err()
				}
			}
		},
		func(config *quic.Config) { config.Allow0RTT = true },
	)

	cache := &h3SessionCache{
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
		stored:             make(chan struct{}, 8),
	}

	builder := surf.NewClient().Builder().Proxy("").Timeout(5 * time.Second).
		Impersonate().Firefox().ForceHTTP3()
	builder.HTTP3Settings().EarlyData(true).AltUsed(false).Set()
	var tracesMu sync.Mutex
	var traces []*earlySettingsTrace
	builder.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		trace := &earlySettingsTrace{requestSent: make(chan struct{})}
		tracesMu.Lock()
		traces = append(traces, trace)
		tracesMu.Unlock()

		go func() {
			select {
			case <-trace.requestSent:
				select {
				case earlySent <- struct{}{}:
				case <-t.Context().Done():
				}
			case <-t.Context().Done():
			}
		}()

		return trace
	}).Set()

	client := builder.TLSConfig(&tls.Config{
		RootCAs:            roots,
		ClientSessionCache: cache,
	}).Build().Unwrap()
	t.Cleanup(func() { client.Close() })

	warm := client.Get(g.String(peer.url + "/warm")).Do()
	require.False(t, warm.IsErr(), "%v", warm.Err())
	require.Equal(t, g.String("ok"), warm.Ok().Body.String().Unwrap())
	<-peer.requests
	for range 2 {
		nextSurfQPACKStream(t, peer)
	}

	waitTicket := func() {
		t.Helper()
		select {
		case <-cache.stored:
		case <-time.After(5 * time.Second):
			t.Fatal("missing HTTP/3 session ticket")
		}
	}
	waitTicket()

	for _, want := range fixture.Requests {
		client.CloseIdleConnections()
		fields := g.NewMapOrd[g.String, g.String]()
		var path, authority string
		for _, field := range want.Fields {
			fields.Insert(g.String(field[0]), g.String(field[1]))
			switch field[0] {
			case ":path":
				path = field[1]
			case ":authority":
				authority = field[1]
			}
		}

		req := client.Get(g.String(peer.url + path)).Fetch().SetHeaders(fields)
		req.GetRequest().Host = authority
		result := req.Do()
		require.False(t, result.IsErr(), "%v", result.Err())
		response := result.Unwrap()
		require.Equal(t, g.String("ok"), response.Body.String().Unwrap())
		require.Equal(t, "HTTP/3.0", response.GetResponse().Proto)
		require.True(t, response.GetResponse().TLS.DidResume)
		require.NotEmpty(t, response.GetResponse().TLS.VerifiedChains)

		var got h3RequestCapture
		select {
		case got = <-peer.requests:
		case err := <-peer.errors:
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			t.Fatal("missing resumed request bytes")
		}

		request, err := hex.DecodeString(want.Request)
		require.NoError(t, err)
		actual := quicvarint.Append(nil, 1)
		actual = quicvarint.Append(actual, uint64(len(got.headerBlock)))
		actual = append(actual, got.headerBlock...)
		require.Equal(t, request, actual, "native HEADERS bytes at %s", path)
		require.Empty(t, got.greaseFrames)
		require.Empty(t, got.body)
		require.True(t, want.Fin, "the raw peer waits for request EOF before responding")

		tracesMu.Lock()
		trace := traces[len(traces)-1]
		tracesMu.Unlock()
		var requestFrames []qlog.StreamFrame
		trace.mu.Lock()
		for _, packet := range trace.packets {
			for _, stream := range packet.streams {
				if stream.StreamID == 0 {
					requestFrames = append(requestFrames, stream)
				}
			}
		}
		trace.mu.Unlock()
		require.NotEmpty(t, requestFrames)
		fin := false
		for _, stream := range requestFrames {
			if stream.Fin {
				fin = true
				require.Positive(t, stream.Length, "FIN must accompany the HEADERS bytes")
				require.EqualValues(t, len(request), stream.Offset+stream.Length)
			}
		}
		require.True(t, fin, "early HEADERS did not carry the bodyless request FIN")

		encoder, err := hex.DecodeString(want.Encoder)
		require.NoError(t, err)
		seen := make(map[uint64]bool)
		for range 2 {
			stream := nextSurfQPACKStream(t, peer)
			require.False(t, seen[stream.typ], "duplicate critical stream")
			seen[stream.typ] = true
			if stream.typ != 2 {
				require.EqualValues(t, 3, stream.typ)
				require.EqualValues(t, 10, stream.id)
				continue
			}

			require.EqualValues(t, 6, stream.id)
			require.NoError(t, stream.stream.SetReadDeadline(time.Now().Add(5*time.Second)))
			instructions := make([]byte, len(encoder)-1)
			_, err := io.ReadFull(stream.stream, instructions)
			require.NoError(t, err)
			require.Equal(
				t,
				encoder,
				append([]byte{2}, instructions...),
				"native encoder bytes at %s",
				path,
			)
		}
		require.True(t, seen[2] && seen[3])
		waitTicket()
	}

	peer.mu.Lock()
	resumed := append([]bool(nil), peer.resumed...)
	peer.mu.Unlock()
	require.Equal(t, []bool{false, true, true}, resumed)
}
