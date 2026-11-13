package surf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
	"github.com/wzshiming/socks5"
)

// Reproduces the native gstatic-style split: an Alt-Svc session cannot satisfy
// a DNS-only job, even when its certificate and ORIGIN authorize that host.
// After the target itself advertises Alt-Svc, it may reuse the original session.
func TestHTTP3CoalescingKeepsDNSAndAltSvcSessionKeysSeparate(t *testing.T) {
	p := newCoalescingTestPeer(t, "", func(port string) []string { return []string{"https://b.test:" + port} }, nil)
	tcp, err := net.Listen("tcp4", "127.0.0.1:"+p.port)
	require.NoError(t, err)
	server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{p.cert}, KeyLogWriter: p.keyLog}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":`+p.port+`"; ma=60`)
		w.Write([]byte("tcp"))
	})}
	go server.ServeTLS(tcp, "", "")
	t.Cleanup(func() { server.Close(); tcp.Close() })
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "b.test": {127, 0, 0, 1}})
	learned := make(chan struct{}, 2)
	b := surf.NewClient().Builder().Impersonate().Chrome().Proxy("").DNS(g.String(d.address))
	b.HTTP3Settings().TCPFallbackDelay(time.Hour).
		HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) { return nil, nil }).
		OnOrigin(func(*quic.Conn, []string) { learned <- struct{}{} }).Set()
	client := b.TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	first, err := coalescingGet(t, client, "a.test", p.port)
	require.NoError(t, err)
	require.Equal(t, 2, first.ProtoMajor)
	second, err := coalescingGet(t, client, "a.test", p.port)
	require.NoError(t, err)
	require.Equal(t, 3, second.ProtoMajor)
	seed := coalescingObserved(t, p)
	select {
	case <-learned:
	case <-time.After(5 * time.Second):
		t.Fatal("no ORIGIN")
	}
	third, err := coalescingGet(t, client, "b.test", p.port)
	require.NoError(t, err)
	require.Equal(t, 2, third.ProtoMajor, "a DNS-only job must not enter an Alt-Svc partition")
	queries := d.count("b.test")
	fourth, err := coalescingGet(t, client, "b.test", p.port)
	require.NoError(t, err)
	require.Equal(t, 3, fourth.ProtoMajor)
	require.Equal(t, seed.connection, coalescingObserved(t, p).connection)
	require.Equal(t, queries, d.count("b.test"), "a matching existing partition and ORIGIN can skip DNS")
	require.EqualValues(t, 1, p.accepted.Load())
}

func TestHTTP3CoalescingChecksAllAdvertisedOriginsBeforeDNS(t *testing.T) {
	first := newCoalescingTestPeer(t, "", nil, nil)
	second := newCoalescingTestPeer(t, "", func(string) []string { return []string{"https://b.test:" + first.port} }, nil)
	roots := first.roots.Clone()
	cert, err := x509.ParseCertificate(second.cert.Certificate[0])
	require.NoError(t, err)
	roots.AddCert(cert)
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "c.test": {127, 0, 0, 1}})
	learned := make(chan struct{}, 2)
	b := coalescingBuilder(first, d).TLSConfig(&tls.Config{RootCAs: roots})
	b.HTTP3Settings().OnOrigin(func(*quic.Conn, []string) { learned <- struct{}{} }).Set()
	client := b.Build().Unwrap()
	defer client.Close()
	_, err = coalescingGet(t, client, "a.test", first.port)
	require.NoError(t, err)
	coalescingObserved(t, first)
	_, err = coalescingGet(t, client, "c.test", second.port)
	require.NoError(t, err)
	coalescingObserved(t, second)
	select {
	case <-learned:
	case <-time.After(5 * time.Second):
		t.Fatal("no ORIGIN from the second connection")
	}
	_, err = coalescingGet(t, client, "b.test", first.port)
	require.NoError(t, err)
	require.Equal(t, "b.test:"+first.port, coalescingObserved(t, second).authority)
	require.Zero(t, d.count("b.test"), "an earlier non-authoritative candidate must not force DNS before checking later ORIGINs")
}

func TestHTTP3CoalescingORIGINMatchesSelectedAltSvcDestination(t *testing.T) {
	for _, advertiseAlternative := range []bool{false, true} {
		t.Run(map[bool]string{false: "origin-only", true: "alternative-destination"}[advertiseAlternative], func(t *testing.T) {
			target := newCoalescingTestPeer(t, "", nil, nil)
			peer := newCoalescingTestPeer(t, "", func(port string) []string {
				if advertiseAlternative {
					return []string{"https://c.test:" + target.port}
				}
				return []string{"https://b.test:" + port}
			}, nil)
			roots := peer.roots.Clone()
			cert, err := x509.ParseCertificate(target.cert.Certificate[0])
			require.NoError(t, err)
			roots.AddCert(cert)
			tcp, err := net.Listen("tcp4", "127.0.0.1:"+peer.port)
			require.NoError(t, err)
			server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{peer.cert}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				alternative := ":" + peer.port
				if strings.HasPrefix(r.Host, "b.test:") {
					alternative = "c.test:" + target.port
				}
				w.Header().Set("Alt-Svc", `h3="`+alternative+`"; ma=60`)
				w.Write([]byte("tcp"))
			})}
			go server.ServeTLS(tcp, "", "")
			t.Cleanup(func() { server.Close(); tcp.Close() })
			d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "b.test": {127, 0, 0, 1}, "c.test": {127, 0, 0, 1}})
			learned := make(chan struct{}, 2)
			b := surf.NewClient().Builder().Impersonate().Chrome().Proxy("").DNS(g.String(d.address))
			b.HTTP3Settings().TCPFallbackDelay(time.Hour).
				HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) { return nil, nil }).
				OnOrigin(func(*quic.Conn, []string) { learned <- struct{}{} }).Set()
			client := b.TLSConfig(&tls.Config{RootCAs: roots}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			for _, host := range []string{"b.test", "a.test", "a.test"} {
				_, err := coalescingGet(t, client, host, peer.port)
				require.NoError(t, err)
			}
			seed := coalescingObserved(t, peer)
			select {
			case <-learned:
			case <-time.After(5 * time.Second):
				t.Fatal("no ORIGIN")
			}
			queries := d.count("c.test")
			_, err = coalescingGet(t, client, "b.test", peer.port)
			require.NoError(t, err)
			if advertiseAlternative {
				require.Equal(t, seed.connection, coalescingObserved(t, peer).connection)
				require.Zero(t, target.accepted.Load())
				require.Equal(t, queries, d.count("c.test"), "the selected destination's ORIGIN permits skipping DNS")
			} else {
				require.Equal(t, "b.test:"+peer.port, coalescingObserved(t, target).authority)
				require.EqualValues(t, 1, target.accepted.Load(), "origin-only ORIGIN cannot authorize a different selected destination")
			}
		})
	}
}

type applicationPoolKey struct{}

func TestHTTP3ApplicationPartitionSeparatesSameAndDifferentAuthorities(t *testing.T) {
	for _, coalesce := range []bool{false, true} {
		t.Run(map[bool]string{false: "dedicated", true: "coalesced"}[coalesce], func(t *testing.T) {
			p := newCoalescingTestPeer(t, "", nil, nil)
			d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "b.test": {127, 0, 0, 1}})
			b := coalescingBuilder(p, d)
			b.HTTP3Settings().ConnectionCoalescing(coalesce).ConnectionPoolPartition(func(ctx context.Context, _ string) string {
				value, _ := ctx.Value(applicationPoolKey{}).(string)
				return value
			}).Set()
			client := b.Build().Unwrap()
			defer client.Close()
			var ids []int32
			for _, request := range []struct{ host, partition string }{{"a.test", "one"}, {"a.test", "two"}, {"b.test", "one"}} {
				ctx := context.WithValue(t.Context(), applicationPoolKey{}, request.partition)
				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+request.host+":"+p.port, nil)
				require.NoError(t, err)
				response, err := client.GetClient().Do(req)
				require.NoError(t, err)
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				ids = append(ids, coalescingObserved(t, p).connection)
			}
			require.NotEqual(t, ids[0], ids[1], "same authority must still respect application isolation")
			if coalesce {
				require.Equal(t, ids[0], ids[2])
				require.EqualValues(t, 2, p.accepted.Load())
			} else {
				require.NotEqual(t, ids[0], ids[2])
				require.EqualValues(t, 3, p.accepted.Load())
			}
		})
	}
}

func TestHTTP3CoalescingRejectsMalformedControlFramesWithoutPublishingOrigins(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		code http3.ErrCode
	}{
		{"ORIGIN before SETTINGS", []byte{0, 12, 0, 4, 0}, http3.ErrCodeMissingSettings},
		{"unknown extension before SETTINGS", []byte{0, 33, 0, 4, 0}, http3.ErrCodeMissingSettings},
		{"truncated origin length", []byte{0, 4, 0, 12, 1, 0}, http3.ErrCodeFrameError},
		{"origin exceeds frame payload", []byte{0, 4, 0, 12, 3, 0, 5, 'x'}, http3.ErrCodeFrameError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newCoalescingTestPeer(t, "", nil, nil, func(string) []byte { return tc.data })
			d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}})
			b := coalescingBuilder(p, d)
			b.HTTP3Settings().OnOrigin(func(*quic.Conn, []string) { t.Error("malformed frame published origin state") }).Set()
			client := b.Build().Unwrap()
			defer client.Close()
			_, err := coalescingGet(t, client, "a.test", p.port)
			require.Error(t, err)
			// Surf may make its normal TCP fallback after the H3 failure. The
			// independent peer observes the actual encrypted CONNECTION_CLOSE.
			select {
			case err = <-p.closed:
			case <-time.After(5 * time.Second):
				t.Fatal("no peer-observed QUIC close")
			}
			var application *quic.ApplicationError
			require.True(t, errors.As(err, &application), "%v", err)
			require.True(t, application.Remote)
			require.EqualValues(t, tc.code, application.ErrorCode)
		})
	}
}

func TestHTTP3OriginFrameLimitRejectsInvalidConfiguration(t *testing.T) {
	for _, limit := range []int{-1, 65537} {
		result := surf.NewClient().Builder().ForceHTTP3().HTTP3Settings().OriginFrameLimit(limit).Set().Build()
		require.True(t, result.IsErr())
		require.True(t, strings.Contains(result.Err().Error(), "origin limit"))
	}
}

func TestHTTP3CoalescingResponseCallbackErrorCannotReplayOrRetireSharedConnection(t *testing.T) {
	p := newCoalescingTestPeer(t, "", nil, nil)
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "b.test": {127, 0, 0, 1}, "c.test": {127, 0, 0, 1}})
	failure := &http3.Error{ErrorCode: http3.ErrCodeRequestRejected}
	b := coalescingBuilder(p, d)
	b.HTTP3Settings().OnResponseHeaders(func(req *http.Request, _ *http.Response) error {
		if strings.HasPrefix(req.URL.Host, "b.test:") {
			return failure
		}
		return nil
	}).Set()
	client := b.Build().Unwrap()
	defer client.Close()
	_, err := coalescingGet(t, client, "a.test", p.port)
	require.NoError(t, err)
	coalescingObserved(t, p)
	_, err = coalescingGet(t, client, "b.test", p.port)
	require.ErrorIs(t, err, failure)
	require.EqualValues(t, 1, coalescingObserved(t, p).connection)
	_, err = coalescingGet(t, client, "c.test", p.port)
	require.NoError(t, err)
	require.EqualValues(t, 1, coalescingObserved(t, p).connection)
	require.EqualValues(t, 1, p.accepted.Load(), "application rejection is not a new-connection retry reason")
}

func TestHTTP3CoalescingRetainsSOCKS5RouteAndSeparatesClients(t *testing.T) {
	p := newCoalescingTestPeer(t, "", func(port string) []string { return []string{"https://b.test:" + port} }, nil)
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}})
	for range 2 {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { listener.Close() })
		proxy := socks5.NewServer()
		proxy.Context = t.Context()
		var relays atomic.Int32
		proxy.ProxyListenPacket = func(ctx context.Context, _, _ string) (net.PacketConn, error) {
			relays.Add(1)
			return (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
		}
		go proxy.Serve(listener)
		learned := make(chan struct{}, 1)
		b := coalescingBuilder(p, d).Proxy(g.String("socks5://" + listener.Addr().String()))
		b.HTTP3Settings().OnOrigin(func(*quic.Conn, []string) { learned <- struct{}{} }).Set()
		client := b.Build().Unwrap()
		t.Cleanup(func() { client.Close() })
		_, err = coalescingGet(t, client, "a.test", p.port)
		require.NoError(t, err)
		first := coalescingObserved(t, p)
		select {
		case <-learned:
		case <-time.After(5 * time.Second):
			t.Fatal("no ORIGIN through SOCKS5")
		}
		_, err = coalescingGet(t, client, "b.test", p.port)
		require.NoError(t, err)
		require.Equal(t, first.connection, coalescingObserved(t, p).connection)
		require.EqualValues(t, 1, relays.Load(), "coalescing must retain the existing proxy relay")
		client.Close()
	}
	require.EqualValues(t, 2, p.accepted.Load(), "independent clients/proxies must establish their own connections")
	require.Zero(t, d.count("b.test"))
}
