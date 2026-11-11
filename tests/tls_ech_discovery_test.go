package surf_test

import (
	"context"
	"crypto/tls"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestBrowserECHDiscoveryWaitsForDNSAndSupportsForcedHTTP3(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, mode := range []string{"automatic-http2", "automatic-http3", "forced-http3"} {
			t.Run(browser+"/"+mode, func(t *testing.T) {
				list, key := testECHConfig(t)
				p := newDiscoveryPeer(t, []tls.EncryptedClientHelloKey{key})
				var queries atomic.Int32
				b := discoveryBuilder(browser).Proxy("").Timeout(3 * time.Second)
				b.HTTP3Settings().TCPFallbackDelay(time.Hour).
					HTTPSRecordsLookup(func(ctx context.Context, name string) ([]surf.HTTPSRecord, error) {
						queries.Add(1)
						require.Equal(t, "_"+p.port+"._https.localhost", name)
						// An ordinary DNS round trip can exceed 50 ms. Its TLS
						// metadata must arrive before either handshake starts.
						timer := time.NewTimer(100 * time.Millisecond)
						defer timer.Stop()
						select {
						case <-ctx.Done():
							return nil, context.Cause(ctx)
						case <-timer.C:
						}
						alpn := []string{"h3", "h2"}
						if mode == "automatic-http2" {
							alpn = []string{"h2"}
						}
						return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", ALPN: alpn, TTL: time.Minute, ECH: list}}, nil
					}).Set()
				if mode == "forced-http3" {
					b.ForceHTTP3()
				}
				client := b.TLSConfig(&tls.Config{RootCAs: p.roots, ServerName: "example.com"}).SecureTLS().Build().Unwrap()
				t.Cleanup(func() { client.Close() })
				for request := range 2 {
					result := client.Get(g.String("https://localhost:" + p.port)).Do()
					require.False(t, result.IsErr(), "%v", result.Err())
					response := result.Ok()
					response.Body.String().Unwrap()
					r := <-p.requests
					want := 3
					// The first TCP response advertises authenticated Alt-Svc;
					// its H3 successor must retain the same DNS ECH policy.
					if mode == "automatic-http2" && request == 0 {
						want = 2
					}
					require.Equal(t, want, r.ProtoMajor)
					require.True(t, r.TLS.ECHAccepted)
					require.True(t, response.GetResponse().TLS.ECHAccepted)
					require.NotEmpty(t, response.GetResponse().TLS.VerifiedChains)
				}
				require.EqualValues(t, 1, queries.Load(), "reuse the positive DNS TTL")
			})
		}
	}
}

func TestForcedHTTP3DiscoveryECHRejectionDoesNotRetryPlaintext(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			list, _ := testECHConfig(t)
			p := newDiscoveryPeer(t, nil)
			var queries atomic.Int32
			b := discoveryBuilder(browser).Proxy("").ForceHTTP3().HTTP3Settings().
				HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
					queries.Add(1)
					return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", ALPN: []string{"h3", "h2"}, TTL: time.Minute, ECH: list}}, nil
				}).Set()
			client := b.TLSConfig(&tls.Config{RootCAs: p.roots, ServerName: "example.com"}).SecureTLS().Timeout(3 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			for range 2 {
				result := client.Get(g.String("https://localhost:" + p.port)).Do()
				require.True(t, result.IsErr())
			}
			require.EqualValues(t, 1, queries.Load())
			require.Zero(t, p.tcpCount.Load())
			require.Zero(t, p.h3Count.Load())
		})
	}
}
