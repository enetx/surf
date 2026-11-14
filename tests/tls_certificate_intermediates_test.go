package surf_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/url"
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
)

type intermediateTestChain struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
	issuer        *x509.Certificate
	leaf          tls.Certificate
}

func TestCertificateIntermediatesProfileReplacementAndProxy(t *testing.T) {
	for _, configure := range []string{"explicit nil", "firefox", "chrome ios", "chrome again", "proxy selector"} {
		t.Run(configure, func(t *testing.T) {
			chain := newIntermediateTestChain(t, "complete candidates")
			endpoint := intermediateTestPeer(t, 2, chain)
			builder := intermediateTestBuilder(2).CertificateIntermediates(chain.intermediates)
			var proxyCalls atomic.Int32
			success := false

			switch configure {
			case "explicit nil":
				builder.CertificateIntermediates(nil)
			case "firefox":
				builder.Impersonate().Firefox()
			case "chrome ios":
				builder.Impersonate().IOS().Chrome()
			case "chrome again":
				builder.Impersonate().Chrome()
			case "proxy selector":
				success = true
				// A request-specific proxy creates a child fingerprint transport.
				// The candidate pool must reach that child too.
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodConnect {
						http.Error(w, "CONNECT required", http.StatusBadRequest)
						return
					}
					target, err := net.Dial("tcp", r.Host)
					if err != nil {
						http.Error(w, "dial failed", http.StatusBadGateway)
						return
					}
					defer target.Close()
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return
					}
					defer conn.Close()
					io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
					proxyCalls.Add(1)
					go io.Copy(target, conn)
					io.Copy(conn, target)
				}))
				t.Cleanup(proxy.Close)
				proxyURL, err := url.Parse(proxy.URL)
				require.NoError(t, err)
				builder.With(func(client *surf.Client) error {
					client.GetTransport().(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
					return nil
				}, 1)
			}

			// Keep DNS out of this local TLS and profile-ownership check.
			builder.HTTP3Settings().Discovery(false).Set()
			client := builder.TLSConfig(&tls.Config{RootCAs: chain.roots}).SecureTLS().Build().Unwrap()
			defer client.Close()
			result := client.Get(g.String(endpoint)).WithContext(context.Background()).Do()
			if success {
				require.False(t, result.IsErr(), "%v", result.Err())
				require.Equal(t, g.String("verified"), result.Unwrap().Body.String().Unwrap())
				require.EqualValues(t, 1, proxyCalls.Load())
			} else {
				require.True(t, result.IsErr(), "profile replacement retained a previous candidate pool")
			}
		})
	}
}

func newIntermediateTestChain(t *testing.T, variant string) intermediateTestChain {
	t.Helper()
	now := time.Now()
	key := func() *ecdsa.PrivateKey {
		value, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return value
	}
	issue := func(
		template, parent *x509.Certificate,
		public *ecdsa.PublicKey,
		signer *ecdsa.PrivateKey,
	) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}
	rootKey, issuerKey, leafKey := key(), key(), key()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Surf chain test root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Surf chain test issuer"},
		NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(12 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		MaxPathLen: 0, MaxPathLenZero: true,
	}
	if variant == "expired issuer" {
		issuerTemplate.NotAfter = now.Add(-time.Hour)
	} else if variant == "issuer is not a CA" {
		issuerTemplate.IsCA = false
		issuerTemplate.KeyUsage = x509.KeyUsageDigitalSignature
		issuerTemplate.MaxPathLen = -1
		issuerTemplate.MaxPathLenZero = false
	}
	issuer := issue(issuerTemplate, root, &issuerKey.PublicKey, rootKey)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	if variant == "wrong hostname" {
		leafTemplate.DNSNames = []string{"other.invalid"}
		leafTemplate.IPAddresses = nil
	}
	leaf := issue(leafTemplate, issuer, &leafKey.PublicKey, issuerKey)
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(issuer)

	return intermediateTestChain{
		roots: roots, intermediates: intermediates, issuer: issuer,
		leaf: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey},
	}
}

func intermediateTestPeer(t *testing.T, protocol int, chain intermediateTestChain) string {
	t.Helper()
	config := &tls.Config{Certificates: []tls.Certificate{chain.leaf}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "verified") })
	if protocol != 3 {
		server := httptest.NewUnstartedServer(handler)
		server.EnableHTTP2 = protocol == 2
		server.TLS = config
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.StartTLS()
		t.Cleanup(server.Close)
		return server.URL
	}

	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http3.Server{
		Handler: handler, TLSConfig: config, EnableDatagrams: true,
		QUICConfig: &quic.Config{EnableDatagrams: true},
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(socket) }()
	t.Cleanup(func() {
		server.Close()
		socket.Close()
		<-done
	})

	return "https://" + socket.LocalAddr().String()
}

func intermediateTestBuilder(protocol int) *surf.Builder {
	builder := surf.NewClient().Builder().Proxy("").Timeout(5 * time.Second).Impersonate().Chrome()
	switch protocol {
	case 1:
		builder.ForceHTTP1()
	case 2:
		builder.ForceHTTP2()
	case 3:
		builder.ForceHTTP3().HTTP3Settings().ConnectionRacing(false).Discovery(false).Set()
	}
	return builder
}

func TestCertificateIntermediatesVerificationAndOwnership(t *testing.T) {
	for _, protocol := range []int{1, 2, 3} {
		for _, scenario := range []string{
			"missing issuer", "complete candidates", "full peer chain", "untrusted root",
			"expired issuer", "issuer is not a CA", "wrong hostname", "copied input", "callback rejected",
		} {
			t.Run(fmt.Sprintf("h%d/%s", protocol, scenario), func(t *testing.T) {
				chain := newIntermediateTestChain(t, scenario)
				pool := chain.intermediates
				success := scenario == "complete candidates" || scenario == "full peer chain"
				if scenario == "missing issuer" || scenario == "full peer chain" {
					pool = nil
				}
				if scenario == "full peer chain" {
					chain.leaf.Certificate = append(chain.leaf.Certificate, chain.issuer.Raw)
				}
				if scenario == "untrusted root" {
					chain.roots = x509.NewCertPool()
				}
				if scenario == "copied input" {
					pool = x509.NewCertPool()
				}
				endpoint := intermediateTestPeer(t, protocol, chain)
				var callbacks atomic.Int32
				builder := intermediateTestBuilder(protocol).CertificateIntermediates(pool)
				if scenario == "copied input" {
					pool.AddCert(chain.issuer)
				}
				client := builder.TLSConfig(&tls.Config{
					RootCAs: chain.roots,
					VerifyPeerCertificate: func(raw [][]byte, verified [][]*x509.Certificate) error {
						callbacks.Add(1)
						if len(raw) != len(chain.leaf.Certificate) || len(verified) == 0 || len(verified[0]) != 3 {
							return fmt.Errorf("unexpected peer or verified chain length")
						}
						if scenario == "callback rejected" {
							return fmt.Errorf("application rejected the verified chain")
						}
						return nil
					},
				}).SecureTLS().Build().Unwrap()
				t.Cleanup(func() { client.Close() })
				// Retired builder values must not alter a new handshake on the client.
				builder.CertificateIntermediates(nil)
				for attempt := range 2 {
					result := client.Get(g.String(endpoint)).Do()
					if !success {
						require.True(t, result.IsErr(), "untrusted or invalid chain was accepted")
						if scenario == "callback rejected" {
							require.EqualValues(t, attempt+1, callbacks.Load())
						} else {
							require.Zero(t, callbacks.Load(), "callback ran before normal verification")
						}
						continue
					}
					require.False(t, result.IsErr(), "%v", result.Err())
					response := result.Unwrap()
					require.Equal(t, g.String("verified"), response.Body.String().Unwrap())
					require.Equal(t, protocol, response.GetResponse().ProtoMajor)
					require.Len(t, response.GetResponse().TLS.PeerCertificates, len(chain.leaf.Certificate))
					require.Len(t, response.GetResponse().TLS.VerifiedChains[0], 3)
					client.CloseIdleConnections()
				}
			})
		}
	}
}
