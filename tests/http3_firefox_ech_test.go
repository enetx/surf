package surf_test

import (
	"crypto/tls"
	"encoding/binary"
	"testing"
	"time"

	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestFirefoxQUICECHMatchesDNSAndIPCaptures(t *testing.T) {
	// Firefox 160 captures: 240-byte ciphertext for DNS SNI at the external
	// endpoint, 208 for 127.0.0.1 without SNI at the independent local peer.
	for _, tc := range []struct {
		name    string
		payload int
	}{
		{"tls.peet.ws", 240}, {"fp.impersonate.pro", 240}, {"127.0.0.1", 208}, {"::1", 208},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newH3Peer(t)
			client := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3().
				TLSConfig(&tls.Config{InsecureSkipVerify: true, ServerName: tc.name}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			peer.request(t, client)
			hello, _ := h3CapturedHello(t, peer)
			value := h3HelloExtensions(t, hello)[65037]
			require.GreaterOrEqual(t, len(value), 10)
			encLength := int(binary.BigEndian.Uint16(value[6:8]))
			require.Equal(t, 32, encLength)
			require.Equal(t, tc.payload, int(binary.BigEndian.Uint16(value[8+encLength:10+encLength])))
		})
	}
}
