package surf_test

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestBrowserECHUsesBuilderDNSForHTTPSAndAddresses(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, order := range []string{"before-profile", "after-profile"} {
			t.Run(browser+"/"+order, func(t *testing.T) {
				list, key := testECHConfig(t)
				peer := newDiscoveryPeer(t, []tls.EncryptedClientHelloKey{key})
				dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { dns.Close() })
				var httpsQueries, addressQueries atomic.Int32
				go func() {
					buf := make([]byte, 4096)
					for {
						n, from, err := dns.ReadFrom(buf)
						if err != nil {
							return
						}
						var query dnsmessage.Message
						if query.Unpack(buf[:n]) != nil || len(query.Questions) != 1 {
							continue
						}
						q := query.Questions[0]
						response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions}
						header := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, Type: q.Type, TTL: 60}
						switch q.Type {
						case dnsmessage.TypeHTTPS:
							httpsQueries.Add(1)
							// ServiceMode target origin.test, h3/h2 ALPN and ECH.
							data := []byte{0, 1, 6, 'o', 'r', 'i', 'g', 'i', 'n', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 6, 2, 'h', '3', 2, 'h', '2', 0, 5}
							data = binary.BigEndian.AppendUint16(data, uint16(len(list)))
							data = append(data, list...)
							response.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.UnknownResource{Type: q.Type, Data: data}}}
						case dnsmessage.TypeA:
							addressQueries.Add(1)
							response.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
						}
						data, err := response.Pack()
						if err == nil {
							dns.WriteTo(data, from)
						}
					}
				}()
				b := surf.NewClient().Builder().Proxy("")
				if order == "before-profile" {
					b.DNS(g.String(dns.LocalAddr().String()))
				}
				if browser == "chrome" {
					b = b.Impersonate().Chrome()
				} else {
					b = b.Impersonate().Firefox()
				}
				if order == "after-profile" {
					b.DNS(g.String(dns.LocalAddr().String()))
				}
				client := b.ForceHTTP3().TLSConfig(&tls.Config{RootCAs: peer.roots, ServerName: "example.com"}).SecureTLS().Timeout(3 * time.Second).Build().Unwrap()
				t.Cleanup(func() { client.Close() })
				response := client.Get(g.String("https://origin.test:" + peer.port)).Do().Unwrap()
				response.Body.String().Unwrap()
				require.Equal(t, 3, response.GetResponse().ProtoMajor)
				require.True(t, response.GetResponse().TLS.ECHAccepted)
				require.NotEmpty(t, response.GetResponse().TLS.VerifiedChains)
				require.Positive(t, httpsQueries.Load())
				require.Positive(t, addressQueries.Load(), "address resolution must also use the configured DNS server")
			})
		}
	}
}
