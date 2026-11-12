package surf_test

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type browserH3Reference struct {
	Settings                 [][]any                    `json:"settings"`
	InitialPacketNumber      uint64                     `json:"initial_packet_number"`
	ClientConnectionIDLength int                        `json:"client_connection_id_length"`
	HeaderOrder              []string                   `json:"header_order"`
	TransportParameters      map[string]json.RawMessage `json:"transport_parameters"`
	TLS                      struct {
		CipherSuites        []uint16          `json:"cipher_suites"`
		Extensions          []uint16          `json:"extensions"`
		Groups              []uint16          `json:"groups"`
		SignatureAlgorithms []uint16          `json:"signature_algorithms"`
		Versions            []uint16          `json:"versions"`
		ALPS                string            `json:"alps"`
		TrustAnchors        string            `json:"trust_anchors"`
		KeyShares           [][]int           `json:"key_shares"`
		ECHCipherSuite      []uint16          `json:"ech_cipher_suite"`
		ExtensionBytes      map[string]string `json:"extension_bytes"`
	} `json:"tls"`
}

func wordsH3(t *testing.T, data []byte) []uint16 {
	t.Helper()
	require.Zero(t, len(data)%2)
	words := make([]uint16, len(data)/2)
	for i := range words {
		words[i] = binary.BigEndian.Uint16(data[2*i:])
	}
	return words
}

func TestChromeHTTP3MatchesIndependentBrowser(t *testing.T) {
	data, err := os.ReadFile("testdata/wire/chromium_158_http3.json")
	require.NoError(t, err)
	var reference browserH3Reference
	require.NoError(t, json.Unmarshal(data, &reference))
	orders := map[string]bool{}
	for range 4 {
		peer := newH3Peer(t)
		client := surf.NewClient().
			Builder().
			Impersonate().
			Windows().
			Chrome().
			ForceHTTP3().
			TLSConfig(&tls.Config{InsecureSkipVerify: true, ServerName: "fp.impersonate.pro"}).
			Timeout(5 * time.Second).
			Build().
			Unwrap()
		capture := peer.request(t, client)
		hello, pn := h3CapturedHello(t, peer)
		require.Equal(t, reference.InitialPacketNumber, pn)
		var names []string
		for _, h := range capture.headers {
			names = append(names, h.Name)
			if h.Name == "sec-ch-ua" {
				require.Equal(t, `"Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"`, h.Value)
			}
		}
		require.Equal(t, reference.HeaderOrder, names)
		ext := checkBrowserH3TLS(t, hello, reference)
		checkBrowserH3Settings(t, capture.settings, reference.Settings)
		params := bytes.NewReader(ext[57])
		values := make(map[uint64][]byte)
		var order []uint64
		grease := 0
		for params.Len() > 0 {
			id, err := quicvarint.Read(params)
			require.NoError(t, err)
			size, err := quicvarint.Read(params)
			require.NoError(t, err)
			value := make([]byte, size)
			_, err = io.ReadFull(params, value)
			require.NoError(t, err)
			values[id] = value
			if id >= 27 && (id-27)%31 == 0 && id != 0xff02de1a {
				grease++
				require.LessOrEqual(t, len(value), 15)
				id = 27
			}
			order = append(order, id)
		}
		require.Equal(t, 1, grease)
		require.Len(t, values, 13)
		require.Empty(t, values[15])
		require.Equal(t, []byte("ORIGNOIP"), values[0x3128])
		require.Len(t, values[17], 12)
		require.EqualValues(t, 1, binary.BigEndian.Uint32(values[17]))
		available := []uint32{binary.BigEndian.Uint32(values[17][4:]), binary.BigEndian.Uint32(values[17][8:])}
		require.Contains(t, available, uint32(1))
		for _, v := range available {
			if v != 1 {
				require.EqualValues(t, 0x0a0a0a0a, v&0x0f0f0f0f)
			}
		}
		for id, want := range map[uint64]uint64{1: 30000, 3: 1472, 4: 15 << 20, 5: 6 << 20, 6: 6 << 20, 7: 6 << 20, 8: 100, 9: 103, 32: 65536} {
			value, _, err := quicvarint.Parse(values[id])
			require.NoError(t, err)
			require.Equal(t, want, value, "transport parameter %d", id)
		}
		require.NotContains(t, values, uint64(11))
		require.NotContains(t, values, uint64(14))
		raw, _ := json.Marshal(order)
		orders[string(raw)] = true
		peer.packet.mu.Lock()
		require.Equal(t, reference.ClientConnectionIDLength, peer.packet.initials[0].sourceCIDLength)
		require.Equal(t, 1250, peer.packet.initials[0].size)
		peer.packet.mu.Unlock()
		client.Close()
	}
	require.Greater(t, len(orders), 1, "transport parameter order was reused across connections")
}

func checkBrowserH3TLS(t *testing.T, hello []byte, reference browserH3Reference) map[uint16][]byte {
	t.Helper()
	ext := h3HelloExtensions(t, hello)
	var ids []uint16
	for id := range ext {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	require.Equal(t, reference.TLS.Extensions, ids)
	pos := 39 + int(hello[38])
	length := int(binary.BigEndian.Uint16(hello[pos:]))
	require.Equal(t, reference.TLS.CipherSuites, wordsH3(t, hello[pos+2:pos+2+length]))
	require.Equal(t, reference.TLS.Groups, wordsH3(t, ext[10][2:]))
	require.Equal(t, reference.TLS.SignatureAlgorithms, wordsH3(t, ext[13][2:]))
	require.Equal(t, reference.TLS.Versions, wordsH3(t, ext[43][1:]))
	require.Equal(t, []byte{0, 3, 2, 'h', '3'}, ext[16])
	require.Equal(t, reference.TLS.ALPS, hex.EncodeToString(ext[17613]))
	require.Equal(t, reference.TLS.TrustAnchors, hex.EncodeToString(ext[51764]))
	shares := ext[51][2:]
	var shape [][]int
	for len(shares) > 0 {
		require.GreaterOrEqual(t, len(shares), 4)
		group, size := int(binary.BigEndian.Uint16(shares)), int(binary.BigEndian.Uint16(shares[2:]))
		require.GreaterOrEqual(t, len(shares)-4, size)
		shape = append(shape, []int{group, size})
		shares = shares[4+size:]
	}
	require.Equal(t, reference.TLS.KeyShares, shape)
	ech := ext[65037]
	require.GreaterOrEqual(t, len(ech), 10)
	if len(reference.TLS.ExtensionBytes) > 0 {
		for id, value := range reference.TLS.ExtensionBytes {
			number, err := strconv.ParseUint(id, 10, 16)
			require.NoError(t, err)
			require.Equal(t, value, hex.EncodeToString(ext[uint16(number)]), "extension %s", id)
		}
	}
	if reference.TLS.ALPS == "" {
		require.EqualValues(t, 1, binary.BigEndian.Uint16(ech[1:]))
		require.Contains(t, []uint16{1, 3}, binary.BigEndian.Uint16(ech[3:]))
		require.Len(t, ech, 282)
	} else {
		require.Equal(
			t,
			reference.TLS.ECHCipherSuite,
			[]uint16{binary.BigEndian.Uint16(ech[1:]), binary.BigEndian.Uint16(ech[3:])},
		)
		require.Contains(t, []int{186, 218, 250, 282}, len(ech))
	}
	return ext
}

func checkBrowserH3Settings(t *testing.T, settings []h3Setting, reference [][]any) {
	t.Helper()
	require.Len(t, settings, len(reference))
	for i, want := range reference {
		if id, ok := want[0].(float64); ok {
			require.EqualValues(t, uint64(id), settings[i].id)
			require.EqualValues(t, uint64(want[1].(float64)), settings[i].value)
		} else {
			require.GreaterOrEqual(t, settings[i].id, uint64(33))
			require.Zero(t, (settings[i].id-33)%31)
		}
	}
}

func TestFirefoxHTTP3MatchesSupportedBrowserParameters(t *testing.T) {
	data, err := os.ReadFile("testdata/wire/firefox_160_http3.json")
	require.NoError(t, err)
	var reference browserH3Reference
	require.NoError(t, json.Unmarshal(data, &reference))
	for range 4 {
		peer := newH3Peer(t)
		client := surf.NewClient().
			Builder().
			Impersonate().
			Windows().
			Firefox().
			ForceHTTP3().
			TLSConfig(&tls.Config{InsecureSkipVerify: true, ServerName: "fp.impersonate.pro"}).
			Timeout(5 * time.Second).
			Build().
			Unwrap()
		capture := peer.request(t, client)
		hello, pn := h3CapturedHello(t, peer)
		require.GreaterOrEqual(t, pn, uint64(1))
		require.LessOrEqual(t, pn, uint64(1024))
		var names []string
		for _, h := range capture.headers {
			names = append(names, h.Name)
		}
		require.Equal(t, reference.HeaderOrder, names)
		checkBrowserH3Settings(t, capture.settings, reference.Settings)
		ext := checkBrowserH3TLS(t, hello, reference)
		params := bytes.NewReader(ext[57])
		values := map[uint64][]byte{}
		var order []uint64
		for params.Len() > 0 {
			id, err := quicvarint.Read(params)
			require.NoError(t, err)
			size, err := quicvarint.Read(params)
			require.NoError(t, err)
			value := make([]byte, size)
			_, err = io.ReadFull(params, value)
			require.NoError(t, err)
			values[id] = value
			if id >= 27 && (id-27)%31 == 0 && id != 0xff02de1a {
				require.Len(t, value, 2)
				id = 27
			}
			order = append(order, id)
		}
		require.Equal(t, []uint64{1, 4, 5, 6, 7, 8, 9, 11, 14, 15, 17, 29, 0xff02de1a, 32}, order)
		for id, raw := range reference.TransportParameters {
			number, err := strconv.ParseUint(id, 10, 64)
			require.NoError(t, err)
			if number == 15 || number == 17 || number == 29 {
				continue
			}
			var want uint64
			require.NoError(t, json.Unmarshal(raw, &want))
			value, _, err := quicvarint.Parse(values[number])
			require.NoError(t, err)
			require.Equal(t, want, value, "transport parameter %d", number)
		}
		require.Len(t, values[15], 3)
		require.Empty(t, values[29])
		require.NotContains(t, values, uint64(3))
		require.Equal(t, []byte{0x43, 0xe8}, values[0xff02de1a], "legacy min_ack_delay advertises 1000 microseconds")
		require.NotContains(t, values, uint64(0x17f7586d2cb571))
		// The fork now implements the compatible switch. Compare the entire
		// version information with the independent browser reference.
		var versions struct {
			Chosen    uint32            `json:"chosen_version"`
			Available []json.RawMessage `json:"available_versions"`
		}
		require.NoError(t, json.Unmarshal(reference.TransportParameters["17"], &versions))
		require.Len(t, values[17], 4*(1+len(versions.Available)))
		require.EqualValues(t, versions.Chosen, binary.BigEndian.Uint32(values[17]))
		for i, expected := range versions.Available {
			actual := binary.BigEndian.Uint32(values[17][4+4*i:])
			if string(expected) == `"GREASE"` {
				require.EqualValues(t, 0x0a0a0a0a, actual&0x0f0f0f0f)
			} else {
				var version uint32
				require.NoError(t, json.Unmarshal(expected, &version))
				require.Equal(t, version, actual)
			}
		}

		peer.packet.mu.Lock()
		require.Equal(t, reference.ClientConnectionIDLength, peer.packet.initials[0].sourceCIDLength)
		peer.packet.mu.Unlock()
		client.Close()
	}
}

func TestHTTP3BrowserProfilesSessionResumption(t *testing.T) {
	for _, firefox := range []bool{false, true} {
		t.Run(map[bool]string{false: "chrome", true: "firefox"}[firefox], func(t *testing.T) {
			peer := newH3Peer(t)
			cache := &h3SessionCache{
				ClientSessionCache: tls.NewLRUClientSessionCache(4),
				stored:             make(chan struct{}, 4),
			}
			profile := surf.NewClient().Builder().Impersonate().Windows()
			var builder *surf.Builder
			if firefox {
				builder = profile.Firefox()
			} else {
				builder = profile.Chrome()
			}
			client := builder.ForceHTTP3().
				TLSConfig(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache, ServerName: "fp.impersonate.pro"}).
				Timeout(5 * time.Second).
				Build().
				Unwrap()
			defer client.Close()
			peer.request(t, client)
			var coldExtensions map[uint16][]byte
			if firefox {
				hello, _ := h3CapturedHello(t, peer)
				coldExtensions = h3HelloExtensions(t, hello)
			}
			select {
			case <-cache.stored:
			case <-time.After(5 * time.Second):
				t.Fatal("browser QUIC template did not store its ticket")
			}
			client.GetClient().CloseIdleConnections()
			if firefox {
				peer.packet.mu.Lock()
				peer.packet.initials = nil
				peer.packet.rawInitials = nil
				peer.packet.mu.Unlock()
			}
			peer.request(t, client)
			peer.mu.Lock()
			resumed := slices.Clone(peer.resumed)
			peer.mu.Unlock()
			require.Equal(t, []bool{false, true}, resumed)
			if firefox {
				hello, _ := h3CapturedHello(t, peer)
				warmExtensions := h3HelloExtensions(t, hello)
				require.NotEmpty(t, warmExtensions[41], "resumed ClientHello must include PSK")
				require.NotEqual(t, coldExtensions[51], warmExtensions[51], "resumption must refresh key shares")
				payloadLength := func(value []byte) int {
					require.GreaterOrEqual(t, len(value), 10)
					enc := int(binary.BigEndian.Uint16(value[6:8]))
					require.GreaterOrEqual(t, len(value), 10+enc)
					return int(binary.BigEndian.Uint16(value[8+enc : 10+enc]))
				}
				cold := payloadLength(coldExtensions[65037])
				warm := payloadLength(warmExtensions[65037])
				require.Greater(t, warm, cold, "NSS GREASE sizing must include the actual resumed PSK")
				require.Zero(t, (warm-16)%32, "NSS pads ClientHelloInner to 32 bytes before the AEAD tag")
			}
		})
	}
}
