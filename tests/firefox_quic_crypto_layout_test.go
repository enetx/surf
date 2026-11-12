package surf_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	firefox "github.com/enetx/surf/profiles/firefox/quic"
	"github.com/stretchr/testify/require"
)

func TestFirefoxInitialCryptoNativePackets(t *testing.T) {
	data, err := os.ReadFile("testdata/wire/firefox_160_initial_crypto.json")
	require.NoError(t, err)
	var reference struct {
		Captures []struct {
			Name            string
			Length          int
			SNIOffset       int                  `json:"sni_offset"`
			SNILength       int                  `json:"sni_length"`
			PacketSizeLimit int                  `json:"packet_size_limit"`
			FrameBudget     int                  `json:"frame_budget"`
			Packets         [][]quic.CryptoRange `json:"packets"`
			Hello           string               `json:"client_hello_hex"`
			SHA256          string               `json:"client_hello_sha256"`
			Hostname        string               `json:"hostname"`
		}
	}
	require.NoError(t, json.Unmarshal(data, &reference))
	require.Len(t, reference.Captures, 4)
	for _, capture := range reference.Captures {
		t.Run(capture.Name, func(t *testing.T) {
			if capture.Hello != "" {
				hello, err := hex.DecodeString(capture.Hello)
				require.NoError(t, err)
				require.Len(t, hello, capture.Length)
				digest := sha256.Sum256(hello)
				require.Equal(t, capture.SHA256, hex.EncodeToString(digest[:]))
				require.Equal(t, capture.Hostname, string(hello[capture.SNIOffset:capture.SNIOffset+capture.SNILength]))
				// Wireshark reassembled this same ClientHello from the recorded
				// out-of-order Initial packets, independently of Surf's parser.
				require.Equal(t, capture.Length-4, int(hello[1])<<16|int(hello[2])<<8|int(hello[3]))
			}
			info := quic.InitialCryptoLayoutInfo{
				Length: capture.Length, SNIOffset: capture.SNIOffset, SNILength: capture.SNILength,
				PacketSizeLimit: capture.PacketSizeLimit, FrameBudget: capture.FrameBudget,
				Remaining: []quic.CryptoRange{{Length: capture.Length}},
			}
			for _, want := range capture.Packets {
				before := slices.Clone(info.Remaining)
				groups := firefox.InitialCryptoLayout(info)
				require.NotEmpty(t, groups)
				require.Equal(t, before, info.Remaining, "policy must not mutate caller ranges")
				require.Equal(t, want, groups[0])
				checkFirefoxCryptoCoverage(t, info, groups)
				info.Remaining = nil
				if len(groups) > 1 {
					info.Remaining = groups[1]
				}
			}
			require.Empty(t, info.Remaining)
		})
	}
}

func TestFirefoxInitialCryptoSourceBranches(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		length, offset, sniLen int
		limit, budget          int
		want                   []quic.CryptoRange
	}{
		{"one packet, right then left", 300, 90, 20, 1236, 1210, []quic.CryptoRange{{Offset: 100, Length: 200}, {Length: 100}}},
		{"odd hostname midpoint rounds down", 300, 90, 19, 1236, 1210, []quic.CryptoRange{{Offset: 99, Length: 201}, {Length: 99}}},
		{"short left, send right suffix", 1900, 162, 18, 1236, 1214, []quic.CryptoRange{{Offset: 1121, Length: 779}, {Length: 171}}},
		{"short right, trim left", 1900, 1470, 18, 1236, 1209, []quic.CryptoRange{{Offset: 1479, Length: 421}, {Length: 529}}},
		{"both exceed balanced limit", 3000, 1490, 20, 1236, 1210, []quic.CryptoRange{{Offset: 1500, Length: 500}, {Length: 500}}},
		{"length varint consumes last byte", 1000, 90, 20, 1236, 990, []quic.CryptoRange{{Offset: 100, Length: 900}, {Length: 81}}},
		{"plaintext limit excludes AEAD", 1240, 90, 20, 1236, 1210, []quic.CryptoRange{{Offset: 720, Length: 520}, {Length: 100}}},
		{"only right fits current packet", 1900, 90, 20, 1236, 100, []quic.CryptoRange{{Offset: 1050, Length: 95}}},
		{"only prefix fits tiny packet", 300, 90, 20, 1236, 4, []quic.CryptoRange{{Length: 1}}},
		{"four-byte offset consumes packet space", 40000, 20000, 20, 1236, 1210, []quic.CryptoRange{{Offset: 20010, Length: 606}, {Length: 593}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := quic.InitialCryptoLayoutInfo{
				Length: tc.length, SNIOffset: tc.offset, SNILength: tc.sniLen,
				PacketSizeLimit: tc.limit, FrameBudget: tc.budget,
				Remaining: []quic.CryptoRange{{Length: tc.length}},
			}
			groups := firefox.InitialCryptoLayout(info)
			require.NotEmpty(t, groups)
			require.Equal(t, tc.want, groups[0])
			checkFirefoxCryptoCoverage(t, info, groups)
		})
	}
}

func TestFirefoxInitialCryptoUsesCurrentUnsentRangesAndBudget(t *testing.T) {
	info := quic.InitialCryptoLayoutInfo{
		Length: 1900, SNIOffset: 90, SNILength: 20, PacketSizeLimit: 1236, FrameBudget: 100,
		Remaining: []quic.CryptoRange{{Length: 1900}},
	}
	first := firefox.InitialCryptoLayout(info)
	require.Equal(t, []quic.CryptoRange{{Offset: 1050, Length: 95}}, first[0])
	// The first packet had no room for offset zero. A larger live budget on
	// the next packet must reconsider that prefix, including its complete SNI.
	info.Remaining, info.FrameBudget = first[1], 1210
	second := firefox.InitialCryptoLayout(info)
	require.Equal(t, []quic.CryptoRange{{Offset: 100, Length: 950}, {Length: 100}}, second[0])
	checkFirefoxCryptoCoverage(t, info, second)

	// An individually retransmitted prefix ends inside the hostname. Neqo's
	// find_sni cannot parse it, so the whole available prefix goes sequentially.
	info.Remaining = []quic.CryptoRange{{Length: 100}}
	require.Equal(t, [][]quic.CryptoRange{{{Length: 100}}}, firefox.InitialCryptoLayout(info))
	// Later ranges retain their offsets and can share a packet across a gap.
	info.Remaining = []quic.CryptoRange{{Offset: 500, Length: 1000}, {Offset: 1700, Length: 200}}
	require.Equal(t, [][]quic.CryptoRange{{{Offset: 500, Length: 1000}, {Offset: 1700, Length: 200}}}, firefox.InitialCryptoLayout(info))

	// ECH only changes the contents/position of the visible hostname. An outer
	// ClientHello or resumed ClientHello uses the same SNI slicing policy.
	info.Remaining = []quic.CryptoRange{{Length: info.Length}}
	plain := firefox.InitialCryptoLayout(info)
	info.ECHOffset, info.ECHLength = 1500, 286
	require.Equal(t, plain, firefox.InitialCryptoLayout(info))
}

func TestFirefoxInitialCryptoNativeFallback(t *testing.T) {
	valid := quic.InitialCryptoLayoutInfo{
		Length: 1900, SNIOffset: 162, SNILength: 18, PacketSizeLimit: 1236, FrameBudget: 1214,
		Remaining: []quic.CryptoRange{{Length: 1900}},
	}
	for _, change := range []func(*quic.InitialCryptoLayoutInfo){
		func(i *quic.InitialCryptoLayoutInfo) { i.Length = 0 },
		func(i *quic.InitialCryptoLayoutInfo) { i.SNIOffset = -1 },
		func(i *quic.InitialCryptoLayoutInfo) { i.SNILength = 0 },
		func(i *quic.InitialCryptoLayoutInfo) { i.SNILength = 2000 },
		func(i *quic.InitialCryptoLayoutInfo) { i.SNIOffset = 1890 },
		func(i *quic.InitialCryptoLayoutInfo) { i.PacketSizeLimit = 0 },
		func(i *quic.InitialCryptoLayoutInfo) { i.FrameBudget = 3 },
		func(i *quic.InitialCryptoLayoutInfo) { i.FrameBudget = 2000 },
		func(i *quic.InitialCryptoLayoutInfo) { i.Remaining = nil },
		func(i *quic.InitialCryptoLayoutInfo) { i.Remaining = []quic.CryptoRange{{Offset: -1, Length: 10}} },
		func(i *quic.InitialCryptoLayoutInfo) { i.Remaining = []quic.CryptoRange{{Length: 0}} },
		func(i *quic.InitialCryptoLayoutInfo) { i.Remaining = []quic.CryptoRange{{Offset: 1890, Length: 11}} },
		func(i *quic.InitialCryptoLayoutInfo) {
			i.Remaining = []quic.CryptoRange{{Length: 100}, {Offset: 99, Length: 10}}
		},
	} {
		info := valid
		change(&info)
		require.Nil(t, firefox.InitialCryptoLayout(info), "%+v", info)
	}
}

func TestFirefoxInitialCryptoOnWire(t *testing.T) {
	for _, hostname := range []string{"fp.impersonate.pro", ""} {
		t.Run(hostname, func(t *testing.T) {
			peer := newH3Peer(t)
			var mu sync.Mutex
			var observed quic.InitialCryptoLayoutInfo
			var firstGroup []quic.CryptoRange
			var first bool
			client := surf.NewClient().Builder().Impersonate().Firefox().QUICSettings().
				InitialCryptoLayout(func(info quic.InitialCryptoLayoutInfo) [][]quic.CryptoRange {
					groups := firefox.InitialCryptoLayout(info)
					mu.Lock()
					if !first {
						first, observed = true, info
						if len(groups) > 0 {
							firstGroup = slices.Clone(groups[0])
						}
					}
					mu.Unlock()
					return groups
				}).Set().ForceHTTP3().
				TLSConfig(&tls.Config{ServerName: hostname, InsecureSkipVerify: true}).
				Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			peer.request(t, client)
			hello, _ := h3CapturedHello(t, peer)
			peer.packet.mu.Lock()
			packet := bytes.Clone(peer.packet.rawInitials[0])
			peer.packet.mu.Unlock()
			plaintext, _, err := h3InitialPlaintext(packet, nil)
			require.NoError(t, err)
			actual := firefoxInitialCryptoFrames(t, plaintext)
			mu.Lock()
			defer mu.Unlock()
			require.True(t, first, "fluent layout callback did not run")
			require.Equal(t, len(hello), observed.Length)
			if hostname == "" {
				require.Equal(t, -1, observed.SNIOffset)
				require.Empty(t, firstGroup, "no-SNI ClientHello must retain sequential framing")
				require.NotEmpty(t, actual)
				require.Zero(t, actual[0].Offset)
				return
			}
			require.Equal(t, hostname, string(hello[observed.SNIOffset:observed.SNIOffset+observed.SNILength]))
			require.Equal(t, firstGroup, actual, "independently decrypted UDP Initial must retain the policy's exact frame order")
			require.Len(t, actual, 2)
			require.Positive(t, actual[0].Offset, "right-hand range must be sent first")
			require.Zero(t, actual[1].Offset)
		})
	}
}

func firefoxInitialCryptoFrames(t *testing.T, plaintext []byte) []quic.CryptoRange {
	t.Helper()
	r := bytes.NewReader(plaintext)
	read := func() uint64 {
		value, err := quicvarint.Read(r)
		require.NoError(t, err)
		return value
	}
	var ranges []quic.CryptoRange
	for r.Len() > 0 {
		switch frame := read(); frame {
		case 0, 1:
		case 6:
			offset, length := read(), read()
			require.LessOrEqual(t, length, uint64(r.Len()))
			ranges = append(ranges, quic.CryptoRange{Offset: int(offset), Length: int(length)})
			_, err := r.Seek(int64(length), 1)
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected first Initial frame type %d", frame)
		}
	}
	return ranges
}

func checkFirefoxCryptoCoverage(t *testing.T, info quic.InitialCryptoLayoutInfo, groups [][]quic.CryptoRange) {
	t.Helper()
	before, after := make([]bool, info.Length), make([]bool, info.Length)
	for _, part := range info.Remaining {
		for i := part.Offset; i < part.Offset+part.Length; i++ {
			before[i] = true
		}
	}
	var frameBytes int
	for g, group := range groups {
		require.NotEmpty(t, group)
		for _, part := range group {
			require.Positive(t, part.Length)
			require.GreaterOrEqual(t, part.Offset, 0)
			require.LessOrEqual(t, part.Offset+part.Length, info.Length)
			for i := part.Offset; i < part.Offset+part.Length; i++ {
				require.False(t, after[i], "duplicate byte %d", i)
				after[i] = true
			}
			if g == 0 {
				frameBytes += 1 + quicvarint.Len(uint64(part.Offset)) + quicvarint.Len(uint64(part.Length)) + part.Length
			}
		}
	}
	require.Equal(t, before, after, "layout must cover exactly the currently unsent bytes")
	require.LessOrEqual(t, frameBytes, info.FrameBudget)
}
