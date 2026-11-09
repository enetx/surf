package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

// Inputs and expected bytes are from actual browsers, never from Surf.
// Leading table updates can move between the first two requests depending on
// when the initial SETTINGS arrives. Compare their aggregate separately from
// each field encoding; subsequent updates are exercised on the same connection.
func TestIndependentBrowserHTTP2Sequence(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "wire", "browser_sequences", browser+"-h2-4096.json"))
			require.NoError(t, err)
			var fixture struct {
				Requests []observedRequest `json:"requests"`
			}
			require.NoError(t, json.Unmarshal(data, &fixture))
			require.Len(t, fixture.Requests, 11)
			directory := t.TempDir()
			cert, _, err := certificate(directory)
			require.NoError(t, err)
			packets, err := newPacketCapture(filepath.Join(directory, "wire.pcap"))
			require.NoError(t, err)
			defer packets.Close()
			records, err := os.Create(filepath.Join(directory, "received.jsonl"))
			require.NoError(t, err)
			defer records.Close()
			s := &captureServer{capacity: 4096, currentLabel: "surf-exact-input", packets: packets, records: records, tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err == nil {
					s.serveH2(conn, "surf-exact-input")
				}
			}()
			input, err := os.Create(filepath.Join(directory, "browser.jsonl"))
			require.NoError(t, err)
			for _, request := range fixture.Requests {
				require.NoError(t, json.NewEncoder(input).Encode(request))
			}
			require.NoError(t, input.Close())
			require.NoError(t, replaySurf(input.Name(), "https://"+listener.Addr().String(), browser, "h2", false))
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("replay connection did not close")
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			require.Empty(t, s.errors)
			require.Len(t, s.requests, len(fixture.Requests))
			var expectedUpdates, actualUpdates []uint64
			decoder := hpack.NewDecoder(1<<20, nil)
			for i, want := range fixture.Requests {
				got := s.requests[i]
				require.Equal(t, want.Path, got.Path)
				require.Equal(t, want.Fields, got.Fields, "%s", want.Path)
				expected, err := hex.DecodeString(want.HeaderBlock)
				require.NoError(t, err)
				decoded, err := decoder.DecodeFull(expected)
				require.NoError(t, err, "browser fixture %s", want.Path)
				var fields []headerField
				for _, f := range decoded {
					fields = append(fields, headerField{f.Name, f.Value})
				}
				require.Equal(t, want.Fields, fields, "browser fixture decode %s", want.Path)
				actual, err := hex.DecodeString(got.HeaderBlock)
				require.NoError(t, err)
				eu, eb := splitTableUpdates(t, expected)
				au, ab := splitTableUpdates(t, actual)
				expectedUpdates = append(expectedUpdates, eu...)
				actualUpdates = append(actualUpdates, au...)
				if browser == "chrome" {
					require.Equal(t, expected, actual, "Chromium raw HPACK differs at %s", want.Path)
				} else {
					require.Equal(t, eb, ab, "Firefox HPACK fields differ at %s", want.Path)
					if i >= 2 {
						require.Equal(t, eu, au, "Firefox table updates differ at %s", want.Path)
					}
				}
			}
			require.Equal(t, expectedUpdates, actualUpdates, "peer table size updates")
			t.Logf("%s: matched all %d independent browser HPACK field sections", browser, len(fixture.Requests))
		})
	}
}

func splitTableUpdates(t *testing.T, block []byte) ([]uint64, []byte) {
	t.Helper()
	var updates []uint64
	for len(block) > 0 && block[0]&0xe0 == 0x20 {
		value := uint64(block[0] & 31)
		block = block[1:]
		if value == 31 {
			for shift := uint(0); ; shift += 7 {
				require.NotEmpty(t, block)
				require.Less(t, shift, uint(63))
				b := block[0]
				block = block[1:]
				value += uint64(b&127) << shift
				if b < 128 {
					break
				}
			}
		}
		updates = append(updates, value)
	}
	return updates, block
}
