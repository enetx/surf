package surf_test

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestECHDiscoveryCustomDialerOwnsResolution(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, protocol := range []string{"http/1.1", "h2", "automatic"} {
			t.Run(browser+"/"+protocol, func(t *testing.T) {
				peer := newDiscoveryPeer(t, nil)
				b := echSessionBuilder(browser, protocol)
				if protocol == "automatic" {
					b = discoveryBuilder(browser).Proxy("")
				}
				var addresses []string
				b.With(func(c *surf.Client) error {
					tr := c.GetTransport().(*http.Transport)
					tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
						addresses = append(addresses, address)
						return new(net.Dialer).DialContext(ctx, network, peer.tcp.Listener.Addr().String())
					}
					return nil
				}, 1)
				client := b.TLSConfig(&tls.Config{RootCAs: peer.roots, ServerName: "example.com"}).SecureTLS().Build().Unwrap()
				t.Cleanup(func() { client.Close() })
				response := client.Get(g.String("https://localhost:" + peer.port)).Do()
				require.False(t, response.IsErr(), "%v", response.Err())
				response.Ok().Body.String().Unwrap()
				require.Len(t, addresses, 1)
				require.True(t, strings.HasPrefix(addresses[0], "localhost:"), "custom dialer received a pre-resolved IP: %v", addresses)
			})
		}
	}
}
