package surf_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestQUICFirefoxCompatibleVersionInformationAndSnapshot(t *testing.T) {
	for _, initial := range []quic.Version{quic.Version1, quic.Version2} {
		other := quic.Version2
		if initial == quic.Version2 {
			other = quic.Version1
		}
		peer := newH3PeerWithQPACK(t, nil, func(c *quic.Config) { c.Versions = []quic.Version{initial} })
		q := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3().QUICSettings().
			CompatibleVersionNegotiation(true).Versions(initial, other)
		client := q.Set().Build().Unwrap()
		t.Cleanup(func() { client.Close() })
		// Build freezes the capability, version list and transport-parameter factory.
		q.CompatibleVersionNegotiation(false).Versions(other)
		peer.request(t, client)
		peer.packet.mu.Lock()
		initialVersion := peer.packet.initials[0].version
		peer.packet.mu.Unlock()
		require.EqualValues(t, initial, initialVersion)
		_, values, _ := quicWireParameters(t, peer)
		info := values[17]
		require.Len(t, info, 16)
		require.EqualValues(t, initial, binary.BigEndian.Uint32(info))
		require.EqualValues(t, 0x0a0a0a0a, binary.BigEndian.Uint32(info[4:])&0x0f0f0f0f)
		require.EqualValues(t, quic.Version2, binary.BigEndian.Uint32(info[8:]))
		require.EqualValues(t, quic.Version1, binary.BigEndian.Uint32(info[12:]))
		if initial == quic.Version1 {
			data, err := os.ReadFile("testdata/wire/firefox_160_rfc9368_endpoint.json")
			require.NoError(t, err)
			var reference struct {
				Native struct {
					PerkText string `json:"perk_text"`
				}
			}
			require.NoError(t, json.Unmarshal(data, &reference))
			// Compare actual decrypted UDP bytes to the independent ordinary browser
			// reference. GREASE entropy is checked separately above.
			expected := fmt.Sprintf(";17:%d@GREASE,%d,%d;", binary.BigEndian.Uint32(info), binary.BigEndian.Uint32(info[8:]), binary.BigEndian.Uint32(info[12:]))
			require.Contains(t, reference.Native.PerkText, expected)
		}

	}
}

func TestQUICCompatibleVersionOptionalNative(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		peer := newH3Peer(t)
		client := surf.NewClient().Builder().ForceHTTP3().QUICSettings().
			CompatibleVersionNegotiation(enabled).Versions(quic.Version1).Set().Build().Unwrap()
		t.Cleanup(func() { client.Close() })
		peer.request(t, client)
		_, values, _ := quicWireParameters(t, peer)
		if enabled {
			require.Equal(t, []byte{0, 0, 0, 1, 0, 0, 0, 1}, values[17])
		} else {
			require.NotContains(t, values, uint64(17))
		}
	}
}
