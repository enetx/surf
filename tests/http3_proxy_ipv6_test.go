package surf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
	"github.com/wzshiming/socks5"
)

func TestHTTP3SOCKS5UDPAndTCPFallback(t *testing.T) {
	for _, udp := range []bool{true, false} {
		t.Run(map[bool]string{true: "udp-relay", false: "udp-disabled"}[udp], func(t *testing.T) {
			peer := newDiscoveryPeer(t, nil)
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			proxy := socks5.NewServer()
			proxy.Context = t.Context()
			var associates atomic.Int32
			proxy.ProxyListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
				associates.Add(1)
				if !udp {
					return nil, errors.New("UDP disabled")
				}
				return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
			}
			go proxy.Serve(listener)
			client := surf.NewClient().Builder().Impersonate().Windows().Chrome().ForceHTTP3().Proxy(g.String("socks5://" + listener.Addr().String())).TLSConfig(&tls.Config{RootCAs: peer.roots, ServerName: "example.com"}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			response := client.Get(g.String("https://127.0.0.1:" + peer.port)).Do().Unwrap()
			require.Equal(t, "ok", response.Body.String().Unwrap().Std())
			want := 3
			if !udp {
				want = 2
			}
			require.Equal(t, want, response.GetResponse().ProtoMajor)
			require.Positive(t, associates.Load())
			require.NotEmpty(t, response.GetResponse().TLS.VerifiedChains)
		})
	}
}

func TestHTTP3IPv6NativeAndChrome(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer seed.Close()
	roots := x509.NewCertPool()
	roots.AddCert(seed.Certificate())
	listener, err := quic.ListenAddr("[::1]:0", http3.ConfigureTLSConfig(seed.TLS.Clone()), nil)
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	defer listener.Close()
	server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "IPv6 HTTP/3") })}
	defer server.Close()
	go server.ServeListener(listener)
	for _, browser := range []string{"native", "chrome"} {
		t.Run(browser, func(t *testing.T) {
			b := surf.NewClient().Builder()
			if browser == "chrome" {
				b = b.Impersonate().Windows().Chrome()
			}
			client := b.ForceHTTP3().Proxy("").TLSConfig(&tls.Config{RootCAs: roots, ServerName: "example.com"}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			response := client.Get(g.String("https://" + listener.Addr().String())).Do().Unwrap()
			require.Equal(t, 3, response.GetResponse().ProtoMajor)
			require.Equal(t, "IPv6 HTTP/3", response.Body.String().Unwrap().Std())
			require.NotEmpty(t, response.GetResponse().TLS.VerifiedChains)
		})
	}
}

func TestHeaderCaseMetadataDoesNotLeakMultiplexed(t *testing.T) {
	peer := newDiscoveryPeer(t, nil)
	for _, protocol := range []int{2, 3} {
		t.Run(fmt.Sprint(protocol), func(t *testing.T) {
			b := surf.NewClient().Builder().Impersonate().Chrome().Proxy("")
			if protocol == 2 {
				b.ForceHTTP2()
			} else {
				b.ForceHTTP3()
			}
			client := b.With(func(r *surf.Request) error {
				r.GetRequest().Header[http.HeaderCaseKey] = []string{"SEC-CH-UA", "bad\r\nname"}
				return nil
			}, 10).TLSConfig(&tls.Config{RootCAs: peer.roots, ServerName: "example.com"}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			response := client.Get(g.String("https://127.0.0.1:" + peer.port)).Do().Unwrap()
			response.Body.String().Unwrap()
			require.Equal(t, protocol, response.GetResponse().ProtoMajor)
			request := <-peer.requests
			require.NotContains(t, request.Header, http.HeaderCaseKey)
		})
	}
}
