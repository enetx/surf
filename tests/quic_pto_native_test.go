package surf_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPTORecoveryNativeReferences(t *testing.T) {
	data, err := os.ReadFile("testdata/wire/pto_recovery/native.json")
	require.NoError(t, err)
	type frame struct{ Type int }
	type packet struct {
		Direction, Space string
		Number           int
		Elapsed          int `json:"elapsed_us"`
		Dropped          bool
		Frames           []frame
	}
	var reference struct {
		Samples []struct {
			Name    string
			Packets []packet
		}
		Anchors []struct {
			Sample, Space   string
			Previous, Probe int
			Gap             int `json:"expected_gap"`
		} `json:"number_gap_anchors"`
		Pair struct {
			Sample  string
			Numbers []int
			Maximum int `json:"maximum_elapsed_us"`
		} `json:"application_pair"`
	}
	require.NoError(t, json.Unmarshal(data, &reference))
	require.Len(t, reference.Samples, 7)
	byName := make(map[string][]packet)
	for _, sample := range reference.Samples {
		byName[sample.Name] = sample.Packets
	}
	for _, anchor := range reference.Anchors {
		var previous, probe *packet
		for _, p := range byName[anchor.Sample] {
			if p.Direction != "client" || p.Space != anchor.Space {
				continue
			}
			if p.Number == anchor.Previous {
				previous = &p
			}
			if p.Number == anchor.Probe {
				probe = &p
			}
		}
		require.NotNil(t, previous)
		require.NotNil(t, probe)
		require.Equal(t, anchor.Gap, probe.Number-previous.Number)
		require.Greater(t, probe.Elapsed, previous.Elapsed)
	}
	var pair []packet
	for _, p := range byName[reference.Pair.Sample] {
		if p.Direction == "client" && p.Space == "application" {
			for _, number := range reference.Pair.Numbers {
				if p.Number == number {
					pair = append(pair, p)
				}
			}
		}
	}
	require.Len(t, pair, 2)
	require.Equal(t, pair[0].Number+1, pair[1].Number)
	require.LessOrEqual(t, pair[1].Elapsed-pair[0].Elapsed, reference.Pair.Maximum)
	var ping bool
	for _, f := range pair[1].Frames {
		ping = ping || f.Type == 1
	}
	require.True(t, ping, "Neqo may fill its second Application probe with PING")
	// Before receiving ServerHello, a routed Handshake packet can prompt
	// Initial CRYPTO recovery without waiting for the client's own PTO.
	packets := byName["firefox-missing-initial-0"]
	missing := false
	handshakeAt := -1
	recovered := false
	for _, p := range packets {
		if p.Direction == "server" && p.Space == "initial" && p.Dropped {
			for _, f := range p.Frames {
				missing = missing || f.Type == 6
			}
		}
		if missing && p.Direction == "server" && p.Space == "handshake" && !p.Dropped && handshakeAt < 0 {
			handshakeAt = p.Elapsed
		}
		if handshakeAt >= 0 && p.Direction == "client" && p.Space == "initial" {
			for _, f := range p.Frames {
				if f.Type == 6 {
					require.Less(t, p.Elapsed-handshakeAt, 100000)
					recovered = true
				}
			}
			if recovered {
				break
			}
		}
	}
	require.True(t, recovered)
}
