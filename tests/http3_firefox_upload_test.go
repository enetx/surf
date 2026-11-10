package surf_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestHTTP3FirefoxFirstReadIndependentBrowserVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/wire/http3_behavior/firefox_upload_vectors.json")
	require.NoError(t, err)
	var fixture struct {
		Cases []struct {
			PeerCapacity uint64 `json:"peer_capacity"`
			Uploads      []struct {
				Method, Path string
				Fields       []struct{ Name, Value string }
				BodyBytes    int   `json:"body_bytes"`
				DataLengths  []int `json:"data_lengths"`
			}
		}
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	for _, capture := range fixture.Cases {
		t.Run(fmt.Sprint(capture.PeerCapacity), func(t *testing.T) {
			trace := new(bodyFrameTrace)
			b := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3()
			b.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }).Set()
			client := b.TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			origin := bodyUploadServer(t)
			require.Len(t, capture.Uploads, 9)
			for _, upload := range capture.Uploads {
				t.Run(upload.Path, func(t *testing.T) {
					trace.mu.Lock()
					trace.sizes = nil
					trace.mu.Unlock()
					payload := strings.Repeat("x", upload.BodyBytes)
					req, err := http.NewRequest(upload.Method, origin+upload.Path, strings.NewReader(payload))
					require.NoError(t, err)
					for _, field := range upload.Fields {
						if field.Name == ":authority" {
							req.Host = field.Value
						}
						if strings.HasPrefix(field.Name, ":") {
							continue
						}
						key := http.CanonicalHeaderKey(field.Name)
						req.Header[key] = append(req.Header[key], field.Value)
						req.Header["Header-Order:"] = append(req.Header["Header-Order:"], field.Name)
					}
					rsp, err := client.GetTransport().RoundTrip(req)
					require.NoError(t, err)
					body, err := io.ReadAll(rsp.Body)
					rsp.Body.Close()
					require.NoError(t, err)
					require.Equal(t, payload, string(body))
					trace.mu.Lock()
					sizes := append([]int(nil), trace.sizes...)
					trace.mu.Unlock()
					require.Equal(t, upload.DataLengths, sizes, "independent Firefox DATA frame boundaries")
				})
			}
		})
	}
}
