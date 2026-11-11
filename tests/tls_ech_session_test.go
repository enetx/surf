package surf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf"
	"github.com/enetx/surf/internal/echretry"
	"github.com/stretchr/testify/require"
)

type echSessionPeer struct {
	url        string
	roots      *x509.CertPool
	states     chan tls.ConnectionState
	handshakes atomic.Int32
}

func newECHSessionPeer(t *testing.T, protocol string, names []string, keys []tls.EncryptedClientHelloKey, rotate bool) *echSessionPeer {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	p := &echSessionPeer{roots: x509.NewCertPool(), states: make(chan tls.ConnectionState, 8)}
	p.roots.AddCert(leaf)
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, EncryptedClientHelloKeys: keys}
	config.SetSessionTicketKeys([][32]byte{{1, 2, 3}})
	if rotate {
		config.GetEncryptedClientHelloKeys = func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			return []tls.EncryptedClientHelloKey{keys[int(p.handshakes.Load())%len(keys)]}, nil
		}
	}
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		attempt := p.handshakes.Add(1)
		if rotate {
			clone := config.Clone()
			clone.GetConfigForClient = nil
			clone.GetEncryptedClientHelloKeys = nil
			clone.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{keys[int(attempt-1)%len(keys)]}
			return clone, nil
		}
		return nil, nil
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.states <- *r.TLS
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		w.Write(body)
	})
	if protocol == "quic" {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		server := &http3.Server{Handler: handler, TLSConfig: config, QUICConfig: &quic.Config{Allow0RTT: true}}
		go server.Serve(pc)
		t.Cleanup(func() { server.Close(); pc.Close() })
		p.url = "https://" + pc.LocalAddr().String()
	} else {
		server := httptest.NewUnstartedServer(handler)
		server.TLS = config
		server.EnableHTTP2 = protocol == "h2"
		server.StartTLS()
		t.Cleanup(server.Close)
		p.url = server.URL
	}
	return p
}

func echSessionBuilder(browser, protocol string) *surf.Builder {
	b := surf.NewClient().Builder().Proxy("").Timeout(5 * time.Second)
	if browser == "native" {
		b.HTTP3Settings().Discovery(true).Set()
	}
	if browser == "chrome" {
		b.Impersonate().Chrome()
	}
	if browser == "firefox" {
		b.Impersonate().Firefox()
	}
	if protocol == "quic" {
		b.ForceHTTP3()
	} else if protocol == "h2" {
		b.ForceHTTP2()
	} else {
		b.ForceHTTP1()
	}
	return b
}

func TestBrowserECHAuthenticatedRetry(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		for _, protocol := range []string{"http/1.1", "h2", "quic"} {
			for _, scenario := range []string{"rotated", "retry-limit", "empty", "wrong-public-name", "wrong-private-name", "untrusted", "early"} {
				if scenario == "early" && protocol != "quic" {
					continue
				}
				t.Run(browser+"/"+protocol+"/"+scenario, func(t *testing.T) {
					old, first := testECHConfig(t)
					_, second := testECHConfig(t)
					keys := []tls.EncryptedClientHelloKey{second}
					names := []string{"example.com", "public.example"}
					if scenario == "retry-limit" {
						keys = []tls.EncryptedClientHelloKey{second, first}
					}
					if scenario == "empty" {
						keys = nil
					}
					if scenario == "wrong-public-name" {
						names = []string{"example.com"}
					}
					if scenario == "wrong-private-name" {
						names = []string{"public.example"}
					}
					p := newECHSessionPeer(t, protocol, names, keys, scenario == "retry-limit")
					cfg := &tls.Config{ServerName: "example.com", RootCAs: p.roots, EncryptedClientHelloConfigList: old}
					if scenario == "untrusted" {
						cfg.RootCAs = x509.NewCertPool()
					}
					b := echSessionBuilder(browser, protocol)
					if scenario == "early" {
						b.HTTP3Settings().EarlyData(true).Set()
					}
					client := b.TLSConfig(cfg).SecureTLS().Build().Unwrap()
					t.Cleanup(func() { client.Close() })
					body := strings.Repeat("private payload\n", 1024)
					var result g.Result[*surf.Response]
					if scenario == "early" {
						result = client.Get(g.String(p.url)).Do()
					} else {
						result = client.Post(g.String(p.url)).Body(body).Do()
					}
					if scenario != "rotated" && scenario != "early" {
						require.True(t, result.IsErr())
						require.Empty(t, p.states, "no HTTP request may reach a rejected handshake")
						want := int32(1)
						if scenario == "retry-limit" || scenario == "wrong-private-name" {
							want = 2
						}
						require.Equal(t, want, p.handshakes.Load(), "retry only authenticated, at most once")
						return
					}
					require.False(t, result.IsErr(), "%v (handshakes %d, authenticated configs %d)", result.Err(), p.handshakes.Load(), len(echretry.Configs(result.Err())))
					got := result.Ok().Body.String().Unwrap()
					if scenario != "early" {
						require.Equal(t, body, string(got))
					}
					state := <-p.states
					require.True(t, state.ECHAccepted)
					require.True(t, result.Ok().GetResponse().TLS.ECHAccepted)
					require.NotEmpty(t, result.Ok().GetResponse().TLS.VerifiedChains)
					require.EqualValues(t, 2, p.handshakes.Load())
					require.Equal(t, old, cfg.EncryptedClientHelloConfigList, "do not mutate caller config")
				})
			}
		}
	}
}

func TestBrowserECHSessionResumption(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, protocol := range []string{"http/1.1", "h2", "quic"} {
			for _, early := range []bool{false, true} {
				if early && protocol != "quic" {
					continue
				}
				t.Run(browser+"/"+protocol+"/early="+fmt.Sprint(early), func(t *testing.T) {
					list, key := testECHConfig(t)
					p := newECHSessionPeer(t, protocol, []string{"example.com", "public.example"}, []tls.EncryptedClientHelloKey{key}, false)
					cache := &h3SessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), stored: make(chan struct{}, 8)}
					b := echSessionBuilder(browser, protocol).Session()
					if early {
						b.HTTP3Settings().EarlyData(true).Set()
					}
					client := b.TLSConfig(&tls.Config{ServerName: "example.com", RootCAs: p.roots,
						EncryptedClientHelloConfigList: list, ClientSessionCache: cache}).SecureTLS().Build().Unwrap()
					t.Cleanup(func() { client.Close() })
					for attempt := range 3 {
						response := client.Get(g.String(p.url)).Do()
						require.False(t, response.IsErr(), "%v", response.Err())
						response.Ok().Body.String().Unwrap()
						state := <-p.states
						require.True(t, state.ECHAccepted)
						require.Equal(t, attempt > 0, state.DidResume)
						require.Equal(t, state.DidResume, response.Ok().GetResponse().TLS.DidResume)
						require.NotEmpty(t, response.Ok().GetResponse().TLS.VerifiedChains)
						if protocol == "quic" {
							select {
							case <-cache.stored:
							case <-time.After(5 * time.Second):
								t.Fatal("no QUIC ticket")
							}
						}
						client.CloseIdleConnections()
					}
				})
			}
		}
	}
}
