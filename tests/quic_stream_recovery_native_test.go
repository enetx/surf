package surf_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSTREAMRecoveryNativeReferences(t *testing.T) {
	type part struct{ ID, Offset, Length int64 }
	type packet struct {
		Direction string
		Number    int64
		Streams   []part
		ACKs      [][2]int64 `json:"acks"`
		Elapsed   int64      `json:"elapsed_us"`
	}
	var reference struct {
		Anchors []struct {
			Browser        string
			Original       int64
			Copies         []int64 `json:"copied_in"`
			AcknowledgedBy int64   `json:"acknowledged_by"`
			Packets        []packet
		}
	}
	data, err := os.ReadFile("testdata/wire/stream_recovery/native.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &reference))
	browsers := make(map[string]int)
	for _, anchor := range reference.Anchors {
		browsers[anchor.Browser]++
		var original, ack packet
		for _, p := range anchor.Packets {
			if p.Direction == "client" && p.Number == anchor.Original {
				original = p
			}
			if p.Direction == "server" && p.Number == anchor.AcknowledgedBy {
				ack = p
			}
		}
		require.NotEmpty(t, original.Streams)
		covered := false
		for _, r := range ack.ACKs {
			covered = covered || r[0] <= original.Number && original.Number <= r[1]
		}
		require.True(t, covered)
		overlap := func(p packet) bool {
			for _, a := range original.Streams {
				for _, b := range p.Streams {
					if a.ID == b.ID && a.Offset < b.Offset+b.Length && b.Offset < a.Offset+a.Length {
						return true
					}
				}
			}
			return false
		}
		require.NotEmpty(t, anchor.Copies)
		copies := 0
		for _, p := range anchor.Packets {
			if p.Direction != "client" || !overlap(p) {
				continue
			}
			if p.Number > original.Number && p.Elapsed < ack.Elapsed {
				copies++
			}
			require.LessOrEqual(t, p.Elapsed, ack.Elapsed, "native sent acknowledged range again")
		}
		require.Positive(t, copies)
	}
	require.Positive(t, browsers["firefox"])
	require.Positive(t, browsers["chromium"])
}
