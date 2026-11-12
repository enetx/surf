package surf_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	"github.com/enetx/surf/profiles/chrome/desktop"
	chromequic "github.com/enetx/surf/profiles/chrome/quic"
	"github.com/enetx/surf/tests/internal/wiretest"
	utls "github.com/enetx/utls"
	"github.com/stretchr/testify/require"
)

// addServerPaddingRequest uses the existing public extension API. The request
// precedes PSK, whose final position is required by RFC 8446 section 4.2.11.
func addServerPaddingRequest(spec *utls.ClientHelloSpec) {
	extension := &utls.GenericExtension{Id: 0x12e0, Data: []byte{0, 0}}
	for i, current := range spec.Extensions {
		if ext, ok := current.(*utls.GenericExtension); ok && ext.Id == 0x12e0 {
			spec.Extensions[i] = extension
			return
		}
		if _, ok := current.(*utls.UtlsPreSharedKeyExtension); ok {
			spec.Extensions = slices.Insert(spec.Extensions, i, utls.TLSExtension(extension))
			return
		}
	}
	spec.Extensions = append(spec.Extensions, extension)
}

// Server padding and NOIP match the native Chromium reference. Public custom
// templates remain usable. These peers ignore padding and do not exercise the
// separate cross-origin connection-coalescing policy.
// https://github.com/google/boringssl/blob/ea9f3a34c3977144c45d272be81842fd891a0bdb/include/openssl/tls1.h
// https://github.com/chromium/chromium/blob/158.0.8127.18/testing/variations/fieldtrial_testing_config.json
func TestChromeExperimentalFieldsThroughPublicBuilders(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
		defer server.Close()
		hellos := make(chan recordedClientHello, 2)
		spec := desktop.NewClientHelloSpec()
		addServerPaddingRequest(&spec)
		builder := surf.NewClient().Builder().Impersonate().Chrome().Proxy("").ForceHTTP1()
		builder.JA().ShuffleExtensions().SetHelloSpec(spec).With(func(c *surf.Client) error {
			transport := c.GetTransport().(*http.Transport)
			dial := transport.DialContext
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := dial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return &clientHelloConn{Conn: conn, hellos: hellos}, nil
			}
			return nil
		})
		client := builder.TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(10 * time.Second).Build().Unwrap()
		defer client.Close()
		client.Get(g.String(server.URL)).Do().Unwrap().Body.String().Unwrap()
		select {
		case hello := <-hellos:
			normalized, _ := wiretest.ClientHello(t, hello.raw, true)
			require.Contains(t, normalized, "ext 4832: 0000\n")
		case <-time.After(5 * time.Second):
			t.Fatal("no TCP ClientHello")
		}
	})
	t.Run("quic", func(t *testing.T) {
		peer := newH3Peer(t)
		client := surf.NewClient().Builder().Impersonate().Chrome().Proxy("").ForceHTTP3().
			QUICSettings().ClientHelloFactory(func() (utls.ClientHelloSpec, error) {
			spec, err := chromequic.NewClientHelloSpec()
			if err == nil {
				addServerPaddingRequest(&spec)
			}
			return spec, err
		}).TransportParameter(0x3128, []byte("ORIGNOIP")).Set().Timeout(10 * time.Second).Build().Unwrap()
		defer client.Close()
		peer.request(t, client)
		hello, _ := h3CapturedHello(t, peer)
		require.Equal(t, []byte{0, 0}, h3HelloExtensions(t, hello)[0x12e0])
		_, parameters, _ := quicWireParameters(t, peer)
		require.Equal(t, []byte("ORIGNOIP"), parameters[0x3128])
	})
	t.Run("default-profile-is-independent", func(t *testing.T) {
		peer := newH3Peer(t)
		client := surf.NewClient().Builder().Impersonate().Chrome().Proxy("").ForceHTTP3().Timeout(10 * time.Second).Build().Unwrap()
		defer client.Close()
		peer.request(t, client)
		hello, _ := h3CapturedHello(t, peer)
		require.Equal(t, []byte{0, 0}, h3HelloExtensions(t, hello)[0x12e0])
		_, parameters, _ := quicWireParameters(t, peer)
		require.Equal(t, []byte("ORIGNOIP"), parameters[0x3128])
	})
}
