package surf_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"math"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func qpackEncodingServer(t *testing.T) string {
	t.Helper()
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certs := certificate.TLS.Certificates
	certificate.Close()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(1, 4096)
	settings.Insert(7, 4)
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: certs}, AdditionalSettings: settings,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Header.Get("X-Value")) })}
	go server.Serve(packet)
	t.Cleanup(func() { server.Close(); packet.Close() })
	return "https://" + packet.LocalAddr().String()
}

func TestHTTP3QPACKEncodingBuilderSnapshots(t *testing.T) {
	var calls atomic.Int32
	builder := surf.NewClient().Builder().ForceHTTP3()
	settings := builder.HTTP3Settings().
		QpackDynamicTable(true).
		QpackHuffman(surf.QPACKHuffmanAuto).
		QpackIndexing(surf.QPACKIndexAll).
		QpackIndexingPolicy(func(name, value string) bool {
			calls.Add(1)
			return strings.HasPrefix(name, "x-")
		}).
		QpackDrainingFraction(.25).
		QpackPostBaseReferences(true).
		QpackLiteralInsertNames(true).
		QpackStopOnInsertionFailure(true).
		QpackMaxTrackedSections(16).
		QpackEncoderZeroCapacity(true).
		QpackEncoderTableCapacity(4096)
	client := settings.Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	// The completed client snapshots every value and the callback itself. Future
	// connections must not inherit invalid settings applied to the original builder.
	settings.QpackDynamicTable(false).QpackHuffman(99).QpackIndexing(99).
		QpackIndexingPolicy(func(string, string) bool { t.Error("mutated policy reached built client"); return false }).
		QpackDrainingFraction(math.NaN()).QpackPostBaseReferences(false).
		QpackLiteralInsertNames(false).QpackStopOnInsertionFailure(false).QpackMaxTrackedSections(1 << 62).
		QpackEncoderZeroCapacity(false).QpackEncoderTableCapacity(1)
	for range 2 {
		origin := qpackEncodingServer(t)
		before := calls.Load()
		for _, value := range []string{"first", "second", "first"} {
			result := client.Get(g.String(origin)).SetHeaders("x-value", value).Do()
			require.False(t, result.IsErr(), "%v", result.Err())
			require.Equal(t, g.String(value), result.Ok().Body.String().Unwrap())
		}
		require.Greater(t, calls.Load(), before, "dynamic insertion policy never ran after peer SETTINGS")
	}
}

func TestHTTP3QPACKRawStringsAndZeroCapacity(t *testing.T) {
	capacity := uint64(0)
	peer := newH3PeerWithQPACK(t, &capacity)
	builder := surf.NewClient().Builder().ForceHTTP3()
	client := builder.HTTP3Settings().QpackDynamicTable(true).
		QpackHuffman(surf.QPACKHuffmanNever).QpackIndexing(surf.QPACKIndexNone).
		QpackNeverIndex("x-marker").QpackEncoderTableCapacity(4096).
		QpackEncoderZeroCapacity(true).Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	for range 2 {
		response := client.Get(g.String(peer.url)).SetHeaders("x-marker", "surf-qpack-raw-marker").Do()
		require.False(t, response.IsErr(), "%v", response.Err())
		require.Equal(t, g.String("ok"), response.Ok().Body.String().Unwrap())
		select {
		case capture := <-peer.requests:
			require.True(t, bytes.Contains(capture.headerBlock, []byte("surf-qpack-raw-marker")), "HuffmanNever must reach the wire")
			require.Equal(t, []byte{0, 0}, capture.headerBlock[:2])
		case <-time.After(5 * time.Second):
			t.Fatal("missing raw-string request")
		}
	}
	stream := nextSurfQPACKStream(t, peer)
	require.EqualValues(t, 2, stream.typ)
	require.Zero(t, readSurfQPACKCapacity(t, stream))
}
