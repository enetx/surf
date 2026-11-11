package surf_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf"
	utls "github.com/enetx/utls"
)

type echInnerPeer struct {
	url      string
	roots    *x509.CertPool
	requests chan *http.Request
	hellos   chan tls.ClientHelloInfo
}

func newECHInnerPeer(t *testing.T, protocol string, group tls.CurveID, keys []tls.EncryptedClientHelloKey) *echInnerPeer {
	t.Helper()
	p := &echInnerPeer{requests: make(chan *http.Request, 4), hellos: make(chan tls.ClientHelloInfo, 4)}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(w, r.Body); err != nil {
			return
		}
		p.requests <- r
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{CurvePreferences: []tls.CurveID{group}, EncryptedClientHelloKeys: keys, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		clone := *h
		clone.Extensions = slices.Clone(h.Extensions)
		clone.CipherSuites = slices.Clone(h.CipherSuites)
		p.hellos <- clone
		return nil, nil
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	p.roots = x509.NewCertPool()
	p.roots.AddCert(server.Certificate())
	p.url = server.URL
	if protocol == "quic" {
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		h3 := &http3.Server{TLSConfig: server.TLS.Clone(), Handler: server.Config.Handler}
		go h3.Serve(udp)
		t.Cleanup(func() { h3.Close(); udp.Close() })
		p.url = "https://" + udp.LocalAddr().String()
	}
	return p
}

func echInnerBuilder(browser, protocol string) *surf.Builder {
	b := surf.NewClient().Builder().Proxy("").Timeout(5 * time.Second)
	if browser == "chrome" {
		b = b.Impersonate().Chrome()
	} else {
		b = b.Impersonate().Firefox()
	}
	if protocol == "quic" {
		return b.ForceHTTP3()
	}
	return b.ForceHTTP2()
}

func TestBrowserECHInnerHandshakeAndKeySelection(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, protocol := range []string{"tcp", "quic"} {
			for _, group := range []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384} {
				for _, ech := range []bool{false, true} {
					name := browser + "/" + protocol + "/" + group.String()
					if ech {
						name += "/ECH"
					}
					t.Run(name, func(t *testing.T) {
						list, key := testECHConfig(t)
						var keys []tls.EncryptedClientHelloKey
						if ech {
							keys = []tls.EncryptedClientHelloKey{key}
						}
						p := newECHInnerPeer(t, protocol, group, keys)
						cfg := &tls.Config{RootCAs: p.roots, ServerName: "example.com"}
						if ech {
							cfg.EncryptedClientHelloConfigList = list
						}
						client := echInnerBuilder(browser, protocol).TLSConfig(cfg).SecureTLS().Build().Unwrap()
						t.Cleanup(func() { client.Close() })
						body := strings.Repeat("verified ECH body\n", 4096)
						response := client.Post(g.String(p.url)).Body(body).Do().Unwrap()
						if got := response.Body.String().Unwrap(); string(got) != body {
							t.Fatal("request or response body changed")
						}
						r := <-p.requests
						if r.TLS.ECHAccepted != ech || r.TLS.CurveID != group {
							t.Fatalf("server state: %+v", r.TLS)
						}
						wantHRR := group == tls.CurveP384 || browser == "chrome" && group == tls.CurveP256
						if r.TLS.HelloRetryRequest != wantHRR {
							t.Fatalf("HRR=%v, want %v", r.TLS.HelloRetryRequest, wantHRR)
						}
						state := response.GetResponse().TLS
						if state == nil || state.ECHAccepted != ech || state.HelloRetryRequest != wantHRR || len(state.VerifiedChains) == 0 {
							t.Fatalf("client TLS verification/state: %+v", state)
						}
						if !ech {
							return
						}
						h := <-p.hellos
						if h.ServerName != "example.com" {
							t.Fatal("server received public SNI instead of private name")
						}
						want := []uint16{0, 0xfe0d, 43, 10, 13, 16, 27, 45, 51}
						if browser == "chrome" {
							want = append(want, 17613, 51764)
							if protocol == "tcp" {
								want = append(want, 5, 18)
							}
						} else {
							want = append(want, 5, 28, 34)
							if protocol == "tcp" {
								want = append(want, 18)
							}
							if h.Extensions[0] != 0xfe0d {
								t.Fatal("NSS inner ECH marker must be first")
							}
						}
						if protocol == "quic" {
							want = append(want, 57)
						}
						got := slices.DeleteFunc(slices.Clone(h.Extensions), func(id uint16) bool { return id&0x0f0f == 0x0a0a && byte(id>>8) == byte(id) })
						slices.Sort(got)
						slices.Sort(want)
						if !slices.Equal(got, want) {
							t.Fatalf("inner extensions=%x, want %x", got, want)
						}
						ciphers := slices.DeleteFunc(slices.Clone(h.CipherSuites), func(id uint16) bool { return id&0x0f0f == 0x0a0a && byte(id>>8) == byte(id) })
						wantCiphers := []uint16{0x1301, 0x1302, 0x1303}
						if browser == "firefox" {
							wantCiphers = []uint16{0x1301, 0x1303, 0x1302}
							if protocol == "tcp" {
								// Native Firefox 160 capture, including legacy cipher
								// identifiers; supported_versions still offers only 1.3.
								wantCiphers = append(wantCiphers, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035)
							}
						}
						if !slices.Equal(ciphers, wantCiphers) {
							t.Fatalf("inner cipher order=%x, want %x", ciphers, wantCiphers)
						}
					})
				}
			}
		}
	}
}

func TestBrowserECHInnerCertificateAndPolicyErrors(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, protocol := range []string{"tcp", "quic"} {
			for _, failure := range []string{"untrusted", "wrong-name", "policy"} {
				t.Run(browser+"/"+protocol+"/"+failure, func(t *testing.T) {
					list, key := testECHConfig(t)
					p := newECHInnerPeer(t, protocol, tls.X25519, []tls.EncryptedClientHelloKey{key})
					cfg := &tls.Config{RootCAs: p.roots, ServerName: "example.com", EncryptedClientHelloConfigList: list}
					if failure == "untrusted" {
						cfg.RootCAs = x509.NewCertPool()
					}
					if failure == "wrong-name" {
						cfg.ServerName = "wrong.example"
					}
					b := echInnerBuilder(browser, protocol)
					sentinel := errors.New("inner policy rejected")
					if failure == "policy" {
						policy := func(utls.ECHClientHelloInfo) (*utls.ECHClientHelloSpec, error) { return nil, sentinel }
						if protocol == "quic" {
							b = b.HTTP3Settings().ECHClientHelloInner(policy).Set()
						} else {
							b = b.JA().ECHClientHelloInner(policy).SetHelloID(utls.HelloFirefox_148)
						}
					}
					client := b.TLSConfig(cfg).SecureTLS().Build().Unwrap()
					t.Cleanup(func() { client.Close() })
					result := client.Get(g.String(p.url)).Do()
					if result.IsOk() {
						t.Fatal("invalid certificate/policy accepted")
					}
					if failure == "policy" && !strings.Contains(result.Err().Error(), sentinel.Error()) {
						t.Fatalf("lost policy error: %v", result.Err())
					}
					select {
					case <-p.requests:
						t.Fatal("application request sent after failure")
					default:
					}
				})
			}
		}
	}
}
