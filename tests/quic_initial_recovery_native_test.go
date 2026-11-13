package surf_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/enetx/quic-go"
	firefox "github.com/enetx/surf/profiles/firefox/quic"
	"github.com/stretchr/testify/require"
)

func mergeRecoveryReference(ranges []quic.CryptoRange) []quic.CryptoRange {
	slices.SortFunc(ranges, func(a, b quic.CryptoRange) int { return a.Offset - b.Offset })
	var merged []quic.CryptoRange
	for _, part := range ranges {
		if len(merged) == 0 || merged[len(merged)-1].Offset+merged[len(merged)-1].Length < part.Offset {
			merged = append(merged, part)
		} else {
			last := &merged[len(merged)-1]
			last.Length = max(last.Offset+last.Length, part.Offset+part.Length) - last.Offset
		}
	}
	return merged
}

func TestInitialRecoveryNativeBrowserReferences(t *testing.T) {
	data, err := os.ReadFile("testdata/wire/initial_recovery/native.json")
	require.NoError(t, err)
	var reference struct {
		Samples []struct {
			Name, Hostname string
			Hello          string `json:"hello_hex"`
			Hash           string `json:"hello_sha256"`
			Length         int
			SNIOffset      int    `json:"sni_offset"`
			SNILength      int    `json:"sni_length"`
			Second         string `json:"second_hello_hex"`
			SecondHash     string `json:"second_hello_sha256"`
			Packets        []struct {
				Number  uint64
				Parts   []quic.CryptoRange
				Budget  int `json:"frame_budget"`
				Dropped bool
			}
		}
	}
	require.NoError(t, json.Unmarshal(data, &reference))
	require.Len(t, reference.Samples, 14)
	for _, sample := range reference.Samples {
		t.Run(sample.Name, func(t *testing.T) {
			hello, err := hex.DecodeString(sample.Hello)
			require.NoError(t, err)
			require.Len(t, hello, sample.Length)
			hash := sha256.Sum256(hello)
			require.Equal(t, sample.Hash, hex.EncodeToString(hash[:]))
			require.Equal(t, sample.Hostname, string(hello[sample.SNIOffset:sample.SNIOffset+sample.SNILength]))
			var first []quic.CryptoRange
			for _, packet := range sample.Packets[:2] {
				first = append(first, packet.Parts...)
			}
			require.Equal(t, []quic.CryptoRange{{Length: sample.Length}}, mergeRecoveryReference(first))
			var lost []quic.CryptoRange
			for _, packet := range sample.Packets {
				if packet.Dropped {
					lost = append(lost, packet.Parts...)
				}
			}
			var recovered int
			if len(lost) > 0 {
				recovered = 2
				if strings.Contains(sample.Name, "third") {
					recovered = 3
				}
			}
			if strings.HasPrefix(sample.Name, "firefox") {
				info := quic.InitialCryptoLayoutInfo{Length: sample.Length, SNIOffset: sample.SNIOffset, SNILength: sample.SNILength, PacketSizeLimit: 1236, Remaining: []quic.CryptoRange{{Length: sample.Length}}}
				for _, packet := range sample.Packets[:2] {
					info.FrameBudget = packet.Budget
					groups := firefox.InitialCryptoLayout(info)
					require.NotEmpty(t, groups)
					require.Equal(t, packet.Parts, groups[0])
					info.Remaining = nil
					if len(groups) > 1 {
						info.Remaining = groups[1]
					}
				}
				require.Empty(t, info.Remaining)
				if len(lost) > 0 {
					info.Remaining = mergeRecoveryReference(lost)
					info.FrameBudget = sample.Packets[recovered].Budget
					if recovered == 3 {
						second, err := hex.DecodeString(sample.Second)
						require.NoError(t, err)
						info.Length += len(second)
					}
					groups := firefox.InitialCryptoLayout(info)
					require.NotEmpty(t, groups)
					require.Equal(t, sample.Packets[recovered].Parts, groups[0], "live recovery layout must match the independently captured native packet")
				}
			} else if strings.HasSuffix(sample.Name, "-loss") {
				require.Equal(t, sample.Packets[1].Number+2, sample.Packets[2].Number, "Chromium skips one number on Initial PTO")
			}
			if sample.Second != "" {
				second, err := hex.DecodeString(sample.Second)
				require.NoError(t, err)
				digest := sha256.Sum256(second)
				require.Equal(t, sample.SecondHash, hex.EncodeToString(digest[:]))
				require.EqualValues(t, 1, second[0])
				for _, packet := range sample.Packets {
					for _, part := range packet.Parts {
						require.LessOrEqual(t, part.Offset+part.Length, sample.Length+len(second))
						if part.Offset >= sample.Length && strings.HasPrefix(sample.Name, "firefox") {
							require.Equal(t, []quic.CryptoRange{{Offset: sample.Length, Length: len(second)}}, packet.Parts)
						}
					}
				}
			}
		})
	}
}
