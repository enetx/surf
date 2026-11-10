package surf_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	h3log "github.com/enetx/quic-go/http3/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type bodyFrameTrace struct {
	mu    sync.Mutex
	sizes []int
}

func (r *bodyFrameTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *bodyFrameTrace) Close() error                     { return nil }
func (r *bodyFrameTrace) RecordEvent(e qlogwriter.Event) {
	if f, ok := e.(h3log.FrameCreated); ok {
		if _, ok := f.Frame.Frame.(h3log.DataFrame); ok {
			r.mu.Lock()
			r.sizes = append(r.sizes, f.Raw.PayloadLength)
			r.mu.Unlock()
		}
	}
}

func bodyUploadServer(t *testing.T) string {
	t.Helper()
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certs := cert.TLS.Certificates
	cert.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: certs}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(w, r.Body)
		if err != nil {
			t.Errorf("upload: %v", err)
		}
	})}
	go server.Serve(pc)
	t.Cleanup(func() { server.Close(); pc.Close() })
	return "https://" + pc.LocalAddr().String()
}

func TestHTTP3RequestBodyProfilesAndOverride(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		want []int
	}{
		{"native", 17000, []int{8192, 8192, 616}},
		{"chrome-small", 17000, []int{17000}},
		{"chrome-min", 1000, []int{1000}},
		{"chrome-max", 400000, []int{371712, 28288}},
		{"firefox", 17000, []int{17000}},
		{"override", 10000, []int{2000, 2000, 1000, 2000, 2000, 1000}},
		{"firefox-override", 10000, []int{2000, 2000, 1000, 2000, 2000, 1000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := surf.NewClient().Builder()
			switch {
			case strings.HasPrefix(tc.name, "chrome"), tc.name == "override":
				b = b.Impersonate().Chrome()
			case strings.HasPrefix(tc.name, "firefox"):
				b = b.Impersonate().Firefox()
			}
			b.ForceHTTP3()
			settings := b.HTTP3Settings()
			if strings.HasSuffix(tc.name, "override") {
				settings.RequestBodyBufferSize(5000).MaxDataFrameSize(2000)
			}
			trace := new(bodyFrameTrace)
			b.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }).Set()
			client := settings.Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			// Mutating a builder must not change the finished transport.
			settings.RequestBodyBufferSize(-1).MaxDataFrameSize(-1)
			payload := strings.Repeat("x", tc.size)
			result := client.Post(g.String(bodyUploadServer(t))).Body(payload).Do()
			require.False(t, result.IsErr(), "%v", result.Err())
			require.Equal(t, g.String(payload), result.Ok().Body.String().Unwrap())
			trace.mu.Lock()
			sizes := append([]int(nil), trace.sizes...)
			trace.mu.Unlock()
			require.Equal(t, tc.want, sizes)
		})
	}
}

func TestHTTP3RequestBodyBuilderValidation(t *testing.T) {
	for _, size := range []int{-1, 16<<20 + 1} {
		require.True(t, surf.NewClient().Builder().ForceHTTP3().HTTP3Settings().RequestBodyBufferSize(size).Set().Build().IsErr())
		require.True(t, surf.NewClient().Builder().ForceHTTP3().HTTP3Settings().MaxDataFrameSize(size).Set().Build().IsErr())
	}
	var calls int
	b := surf.NewClient().Builder().ForceHTTP3()
	c := b.HTTP3Settings().RequestBodyBufferSizePolicy(func(length int64) int { calls++; require.EqualValues(t, 17, length); return -1 }).Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Build().Unwrap()
	t.Cleanup(func() { c.Close() })
	result := c.Post(g.String(bodyUploadServer(t))).Body(strings.Repeat("x", 17)).Do()
	require.True(t, result.IsErr())
	require.Equal(t, 1, calls)
}
