package surf_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	chromecommon "github.com/enetx/surf/profiles/chrome/common"
	firefoxcommon "github.com/enetx/surf/profiles/firefox/common"
	"github.com/stretchr/testify/require"
	"github.com/wzshiming/socks5"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/net/dns/dnsmessage"
)

type discoveryPeer struct {
	tcp               *httptest.Server
	h3                *http3.Server
	port              string
	roots             *x509.CertPool
	requests          chan *http.Request
	tcpCount, h3Count atomic.Int32
	clear             atomic.Bool
}

func newDiscoveryPeer(t *testing.T, echKeys []tls.EncryptedClientHelloKey, wrappers ...func(net.PacketConn) net.PacketConn) *discoveryPeer {
	t.Helper()
	p := &discoveryPeer{requests: make(chan *http.Request, 32)}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 3 {
			p.h3Count.Add(1)
		} else {
			p.tcpCount.Add(1)
		}
		if p.clear.Load() {
			w.Header().Set("Alt-Svc", "clear")
		} else {
			w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=60`, p.port))
		}
		p.requests <- r
		io.Copy(w, r.Body)
		io.WriteString(w, "ok")
	})
	p.tcp = httptest.NewUnstartedServer(handler)
	p.tcp.EnableHTTP2 = true
	p.tcp.TLS = &tls.Config{EncryptedClientHelloKeys: echKeys}
	udp := reserveRacingUDP(t, p.tcp)
	p.tcp.StartTLS()
	_, p.port, _ = net.SplitHostPort(p.tcp.Listener.Addr().String())
	p.roots = x509.NewCertPool()
	p.roots.AddCert(p.tcp.Certificate())
	p.h3 = &http3.Server{Handler: handler, TLSConfig: p.tcp.TLS.Clone()}
	p.h3.TLSConfig.EncryptedClientHelloKeys = echKeys
	var packet net.PacketConn = udp
	for _, wrap := range wrappers {
		packet = wrap(packet)
	}
	go p.h3.Serve(packet)
	t.Cleanup(func() { p.h3.Close(); udp.Close(); p.tcp.Close() })
	return p
}

func discoveryBuilder(browser string) *surf.Builder {
	b := surf.NewClient().Builder()
	switch browser {
	case "chrome":
		return b.Impersonate().Windows().Chrome()
	case "firefox":
		return b.Impersonate().Windows().Firefox()
	default:
		return b.HTTP3Settings().Discovery(true).Set()
	}
}

func TestHTTP3DiscoveryAuthenticatedAltSvcAndClear(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			p := newDiscoveryPeer(t, nil)
			client := discoveryBuilder(browser).HTTP3Settings().TCPFallbackDelay(time.Hour).Set().
				TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			for i := range 4 {
				if i == 2 {
					p.clear.Store(true)
				}
				response := client.Get(g.String(p.tcp.URL)).Do().Unwrap()
				require.Equal(t, g.String("ok"), response.Body.String().Unwrap())
				require.NotNil(t, response.GetResponse().TLS)
				require.NotEmpty(t, response.GetResponse().TLS.VerifiedChains)
				request := <-p.requests
				if i == 0 || i == 3 {
					require.Equal(t, 2, request.ProtoMajor)
				} else {
					require.Equal(t, 3, request.ProtoMajor)
				}
			}
			require.EqualValues(t, 2, p.tcpCount.Load())
			require.EqualValues(t, 2, p.h3Count.Load())
		})
	}
}

func TestHTTP3DiscoveryRejectsUnverifiedAdvertisement(t *testing.T) {
	p := newDiscoveryPeer(t, nil)
	client := discoveryBuilder("firefox").TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	for range 2 {
		response := client.Get(g.String(p.tcp.URL)).Do().Unwrap()
		response.Body.String()
		require.Equal(t, 2, (<-p.requests).ProtoMajor)
	}
	require.Zero(t, p.h3Count.Load())
}

func TestHTTP3DiscoveryHTTPSRecordKeepsOriginAndAltUsed(t *testing.T) {
	p := newDiscoveryPeer(t, nil)
	var calls atomic.Int32
	client := discoveryBuilder("firefox").HTTP3Settings().TCPFallbackDelay(time.Hour).
		HTTPSRecordsLookup(func(_ context.Context, name string) ([]surf.HTTPSRecord, error) {
			calls.Add(1)
			require.Equal(t, "_"+p.port+"._https.example.com", name)
			return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", ALPN: []string{"h3"}, TTL: time.Minute}}, nil
		}).Set().TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	url := "https://example.com:" + p.port
	for range 2 {
		response := client.Get(g.String(url)).Do().Unwrap()
		response.Body.String()
		r := <-p.requests
		require.Equal(t, 3, r.ProtoMajor)
		require.Equal(t, "example.com:"+p.port, r.Host)
		require.Equal(t, "example.com", r.TLS.ServerName)
		require.Equal(t, "127.0.0.1:"+p.port, r.Header.Get("Alt-Used"))
	}
	require.EqualValues(t, 1, calls.Load())
}

func testECHConfig(t *testing.T) ([]byte, tls.EncryptedClientHelloKey) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1)
		b.AddUint16(0x20)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
		b.AddUint8(32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.example")) })
		b.AddUint16(0)
	})
	config := b.BytesOrPanic()
	list := cryptobyte.NewBuilder(nil)
	list.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(config) })
	return list.BytesOrPanic(), tls.EncryptedClientHelloKey{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}
}

func TestHTTP3DiscoveryRealECHWithOfficialTLS(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			list, key := testECHConfig(t)
			p := newDiscoveryPeer(t, []tls.EncryptedClientHelloKey{key})
			client := discoveryBuilder(browser).HTTP3Settings().TCPFallbackDelay(time.Hour).
				HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
					return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", ALPN: []string{"h3"}, TTL: time.Minute, ECH: list}}, nil
				}).
				Set().TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			result := client.Get(g.String("https://example.com:" + p.port)).Do()
			require.False(t, result.IsErr(), "%v", result.Err())
			response := result.Unwrap()
			response.Body.String()
			r := <-p.requests
			require.Equal(t, 3, r.ProtoMajor)
			require.True(t, r.TLS.ECHAccepted)
			require.Equal(t, "example.com", r.TLS.ServerName)
		})
	}
}

func TestBrowserAlternativeBackoffSourceDefaults(t *testing.T) {
	for i, want := range []time.Duration{5 * time.Minute, 5 * time.Minute, 10 * time.Minute, 20 * time.Minute} {
		require.Equal(t, want, chromecommon.AlternativeServiceBackoff(uint32(i+1)))
		require.Equal(t, 2*time.Second, firefoxcommon.AlternativeServiceBackoff(uint32(i+1)))
	}
	require.Equal(t, 48*time.Hour, chromecommon.AlternativeServiceBackoff(^uint32(0)))
}

func TestHTTP3DiscoveryTCPFallbackRetainsECH(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			list, key := testECHConfig(t)
			p := newDiscoveryPeer(t, []tls.EncryptedClientHelloKey{key}, func(conn net.PacketConn) net.PacketConn {
				return &racingUDP{PacketConn: conn, seen: make(chan struct{})}
			})
			// UDP handshakes are dropped, while TCP remains available. TCP still connects to the
			// origin and must retain ECH instead of silently retrying in plaintext.
			client := discoveryBuilder(browser).With(func(c *surf.Client) error {
				base := c.GetTransport().(*http.Transport)
				base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
					return new(net.Dialer).DialContext(ctx, network, p.tcp.Listener.Addr().String())
				}
				return nil
			}).HTTP3Settings().TCPFallbackDelay(0).HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
				return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", ALPN: []string{"h3"}, TTL: time.Minute, ECH: list}}, nil
			}).Set().TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			result := client.Get(g.String("https://example.com:" + p.port)).Do()
			require.False(t, result.IsErr(), "%v", result.Err())
			response := result.Unwrap()
			response.Body.String()
			r := <-p.requests
			require.Equal(t, 2, r.ProtoMajor)
			require.True(t, r.TLS.ECHAccepted)
			require.True(t, response.GetResponse().TLS.ECHAccepted)
		})
	}
}

func TestHTTP3DiscoveryECHRejectionDoesNotDowngrade(t *testing.T) {
	list, _ := testECHConfig(t)
	p := newDiscoveryPeer(t, nil)
	client := discoveryBuilder("firefox").With(func(c *surf.Client) error {
		base := c.GetTransport().(*http.Transport)
		base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, p.tcp.Listener.Addr().String())
		}
		return nil
	}).HTTP3Settings().TCPFallbackDelay(0).HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
		return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", ALPN: []string{"h3"}, TTL: time.Minute, ECH: list}}, nil
	}).Set().TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	for range 2 {
		result := client.Get(g.String("https://example.com:" + p.port)).Do()
		require.True(t, result.IsErr())
	}
	require.Zero(t, p.tcpCount.Load())
	require.Zero(t, p.h3Count.Load())
}

func TestHTTP3DiscoveryPreservesPlainHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "plain") }))
	defer server.Close()
	for _, browser := range []string{"native", "chrome", "firefox"} {
		client := discoveryBuilder(browser).Build().Unwrap()
		response := client.Get(g.String(server.URL)).Do().Unwrap()
		require.Equal(t, g.String("plain"), response.Body.String().Unwrap())
		require.Equal(t, 1, response.GetResponse().ProtoMajor)
		client.Close()
	}
}

func TestQUICAddressFallbackClosesLosingHandshake(t *testing.T) {
	p := newDiscoveryPeer(t, nil)
	var attempts atomic.Int32
	client := discoveryBuilder("firefox").With(func(c *surf.Client) error {
		c.GetDialer().Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				server.SetDeadline(time.Now().Add(time.Second))
				var prefix [2]byte
				if _, err := io.ReadFull(server, prefix[:]); err != nil {
					return
				}
				data := make([]byte, binary.BigEndian.Uint16(prefix[:]))
				if _, err := io.ReadFull(server, data); err != nil {
					return
				}
				var query dnsmessage.Message
				if query.Unpack(data) != nil {
					return
				}
				response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RCode: dnsmessage.RCodeNameError}, Questions: query.Questions}
				data, err := response.Pack()
				if err != nil {
					return
				}
				binary.BigEndian.PutUint16(prefix[:], uint16(len(data)))
				server.Write(append(prefix[:], data...))
			}()
			return client, nil
		}}
		return nil
	}).HTTP3Settings().TCPFallbackDelay(time.Hour).HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
		return []surf.HTTPSRecord{{Priority: 1, Target: "binding.invalid", ALPN: []string{"h3"}, TTL: time.Minute,
			IPv4Hint: []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}}}, nil
	}).Set().QUICSettings().AddressFallbackDelay(10 * time.Millisecond).
		Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { attempts.Add(1); return nil }).
		Set().TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	response := client.Get(g.String("https://example.com:" + p.port)).Do().Unwrap()
	require.Equal(t, g.String("ok"), response.Body.String().Unwrap())
	require.Equal(t, 3, response.GetResponse().ProtoMajor)
	require.EqualValues(t, 2, attempts.Load(), "the unreachable first address must not block the second")
	require.EqualValues(t, 1, p.h3Count.Load(), "only the winner sends an application request")
}

func TestHTTPSBindingTCPOnlyAlternativeKeepsOriginAndECH(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			list, key := testECHConfig(t)
			p := newDiscoveryPeer(t, []tls.EncryptedClientHelloKey{key})
			port, err := strconv.ParseUint(p.port, 10, 16)
			require.NoError(t, err)
			client := discoveryBuilder(browser).HTTP3Settings().HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
				return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", Port: uint16(port), ALPN: []string{"h2"}, NoDefaultALPN: true, TTL: time.Minute, ECH: list}}, nil
			}).Set().TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			response := client.Get("https://example.com").Do().Unwrap()
			response.Body.String().Unwrap()
			received := <-p.requests
			require.Equal(t, 2, received.ProtoMajor)
			require.Equal(t, "example.com", received.Host)
			require.Equal(t, "example.com", received.TLS.ServerName)
			require.True(t, received.TLS.ECHAccepted)
			require.Zero(t, p.h3Count.Load())
		})
	}
}

func TestHTTPSBindingNoDefaultALPNPreventsTCPBackup(t *testing.T) {
	p := newDiscoveryPeer(t, nil)
	var tcpDials atomic.Int32
	client := discoveryBuilder("firefox").With(func(c *surf.Client) error {
		c.GetTransport().(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			tcpDials.Add(1)
			return new(net.Dialer).DialContext(ctx, network, p.tcp.Listener.Addr().String())
		}
		return nil
	}).HTTP3Settings().TCPFallbackDelay(0).HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
		return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", ALPN: []string{"h3"}, NoDefaultALPN: true, TTL: time.Minute}}, nil
	}).Set().TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	response := client.Get(g.String("https://example.com:" + p.port)).Do().Unwrap()
	response.Body.String().Unwrap()
	require.Equal(t, 3, response.GetResponse().ProtoMajor)
	require.Zero(t, tcpDials.Load())
}

func TestHTTP3DiscoveryProxiesDoNotTriggerLocalHTTPSLookup(t *testing.T) {
	for _, kind := range []string{"connect", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			p := newDiscoveryPeer(t, nil)
			builder := discoveryBuilder("firefox")
			if kind == "connect" {
				builder.Proxy(g.String(newHTTPConnectProxy(t).URL))
			} else {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer listener.Close()
				proxy := socks5.NewServer()
				proxy.Context = t.Context()
				go proxy.Serve(listener)
				builder.Proxy(g.String("socks5://" + listener.Addr().String()))
			}
			var lookups atomic.Int32
			client := builder.HTTP3Settings().HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) { lookups.Add(1); return nil, nil }).
				Set().TLSConfig(&tls.Config{RootCAs: p.roots, ServerName: "example.com"}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			response := client.Get(g.String("https://localhost:" + p.port)).Do().Unwrap()
			response.Body.String().Unwrap()
			require.Equal(t, 2, response.GetResponse().ProtoMajor)
			require.Zero(t, lookups.Load())
		})
	}
}
