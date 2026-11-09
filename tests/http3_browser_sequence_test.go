package surf_test

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

// Actual browser field sections at peer capacity zero isolate static encoding
// from the outbound dynamic encoder, which Surf does not implement yet.
func TestIndependentBrowserHTTP3Sequence(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			data, err := os.ReadFile("testdata/wire/browser_sequences/" + browser + "-h3-0.json")
			require.NoError(t, err)
			var fixture struct {
				Requests []struct {
					Path   string                         `json:"path"`
					Block  string                         `json:"header_block_hex"`
					Fields []struct{ Name, Value string } `json:"fields"`
				} `json:"requests"`
				Control map[string]struct {
					Settings   [][]struct{ ID, Value string } `json:"settings"`
					Priorities []struct {
						Stream uint64
						Value  string
					} `json:"priorities"`
				} `json:"control"`
			}
			require.NoError(t, json.Unmarshal(data, &fixture))
			require.Len(t, fixture.Requests, 11)
			capacity := uint64(0)
			peer := newH3PeerWithQPACK(t, &capacity)
			im := surf.NewClient().Builder().Impersonate().MacOS()
			var builder *surf.Builder
			if browser == "firefox" {
				builder = im.Firefox()
			} else {
				builder = im.Chrome()
			}
			client := builder.ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Build().Unwrap()
			defer client.Close()
			for i, want := range fixture.Requests {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				req, err := http.NewRequestWithContext(ctx, "GET", peer.url+want.Path, nil)
				require.NoError(t, err)
				var regular, pseudo []string
				seen := make(map[string]bool)
				for _, f := range want.Fields {
					if strings.HasPrefix(f.Name, ":") {
						pseudo = append(pseudo, f.Name)
						if f.Name == ":authority" {
							req.Host = f.Value
						}
						continue
					}
					key := http.CanonicalHeaderKey(f.Name)
					req.Header[key] = append(req.Header[key], f.Value)
					if !seen[f.Name] {
						regular = append(regular, f.Name)
						seen[f.Name] = true
					}
				}
				req.Header["Header-Order:"] = regular
				req.Header["PHeader-Order:"] = pseudo
				response, err := client.GetClient().Transport.RoundTrip(req)
				require.NoError(t, err)
				_, err = io.Copy(io.Discard, response.Body)
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				cancel()
				var got h3RequestCapture
				select {
				case got = <-peer.requests:
				case err := <-peer.errors:
					t.Fatal(err)
				case <-time.After(5 * time.Second):
					t.Fatal("missing browser replay request")
				}
				require.Len(t, got.headers, len(want.Fields))
				for j, f := range want.Fields {
					require.Equal(t, f.Name, got.headers[j].Name, want.Path)
					require.Equal(t, f.Value, got.headers[j].Value, want.Path)
				}
				if browser == "firefox" {
					block, err := hex.DecodeString(want.Block)
					require.NoError(t, err)
					require.Equal(t, block, got.headerBlock, "Firefox QPACK differs at %s", want.Path)
				}
				if i == 0 {
					var expected, actual []h3Setting
					for _, setting := range fixture.Control["browser"].Settings[0] {
						id, err := strconv.ParseUint(setting.ID, 0, 64)
						require.NoError(t, err)
						value, err := strconv.ParseUint(setting.Value, 10, 64)
						require.NoError(t, err)
						if id >= 33 && (id-33)%31 == 0 {
							continue
						}
						expected = append(expected, h3Setting{id, value})
					}
					for _, setting := range got.settings {
						if setting.id < 33 || (setting.id-33)%31 != 0 {
							actual = append(actual, setting)
						}
					}
					require.Equal(t, expected, actual, "ordered browser SETTINGS")
					grease := nextSurfControlFrame(t, peer)
					require.GreaterOrEqual(t, grease.kind, uint64(33))
					require.Zero(t, (grease.kind-33)%31)
				}
				if browser == "chrome" {
					priority := nextSurfControlFrame(t, peer)
					require.EqualValues(t, 0xf0700, priority.kind)
					stream, n, err := quicvarint.Parse(priority.payload)
					require.NoError(t, err)
					wantPriority := fixture.Control["browser"].Priorities[i]
					require.Equal(t, wantPriority.Stream, stream)
					require.Equal(t, wantPriority.Value, string(priority.payload[n:]))
				}
			}
			if browser == "firefox" {
				select {
				case f := <-peer.controlFrames:
					t.Fatalf("unexpected Firefox control frame %d", f.kind)
				case <-time.After(30 * time.Millisecond):
				}
			}
		})
	}
}
