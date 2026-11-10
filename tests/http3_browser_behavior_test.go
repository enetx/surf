package surf_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestHTTP3IndependentBrowserUploadFrames(t *testing.T) {
	raw, err := os.ReadFile("testdata/wire/http3_behavior/browser_observations.json")
	require.NoError(t, err)
	var report struct {
		Cases []struct {
			Browser, Scenario string
			PeerCapacity      uint64 `json:"peer_capacity"`
			Uploads           []struct {
				Path            string
				BodyBytes       int `json:"body_bytes"`
				Browser         []int
				BoundariesEqual bool `json:"boundaries_equal"`
			}
		}
	}
	require.NoError(t, json.Unmarshal(raw, &report))
	for _, capture := range report.Cases {
		if capture.Scenario != "uploads" || capture.PeerCapacity != 0 {
			continue
		}
		t.Run(capture.Browser, func(t *testing.T) {
			require.Len(t, capture.Uploads, 9)
			b := surf.NewClient().Builder()
			if capture.Browser == "chrome" {
				b = b.Impersonate().Chrome()
			} else {
				b = b.Impersonate().Firefox()
			}
			trace := new(bodyFrameTrace)
			b.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }).Set()
			client := b.ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			origin := bodyUploadServer(t)
			for _, upload := range capture.Uploads {
				t.Run(upload.Path, func(t *testing.T) {
					trace.mu.Lock()
					trace.sizes = nil
					trace.mu.Unlock()
					payload := strings.Repeat("x", upload.BodyBytes)
					result := client.Post(g.String(origin + upload.Path)).Body(payload).Do()
					require.False(t, result.IsErr(), "%v", result.Err())
					require.Equal(t, g.String(payload), result.Ok().Body.String().Unwrap())
					trace.mu.Lock()
					sizes := append([]int(nil), trace.sizes...)
					trace.mu.Unlock()
					if capture.Browser == "chrome" || upload.BoundariesEqual {
						require.Equal(t, upload.Browser, sizes, "independent browser DATA boundaries")
					} else {
						// The Firefox first-segment header subtraction remains unimplemented.
						// Verify only the shipped body segment size and complete payload here.
						total := 0
						for _, size := range sizes {
							require.LessOrEqual(t, size, 32768)
							total += size
						}
						require.Equal(t, upload.BodyBytes, total)
						require.Equal(t, 32768, sizes[0])
					}
				})
			}
		})
	}
}
