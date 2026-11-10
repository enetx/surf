package surf_test

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type peerAckFrequencyClientTrace struct {
	mu            sync.Mutex
	frames        []qlog.LegacyAckFrequencyFrame
	packetTypes   []qlog.PacketType
	initialWindow uint64
}

func (t *peerAckFrequencyClientTrace) AddProducer() qlogwriter.Recorder { return t }
func (t *peerAckFrequencyClientTrace) Close() error                     { return nil }
func (t *peerAckFrequencyClientTrace) RecordEvent(event qlogwriter.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if parameters, ok := event.(qlog.RecoveryParametersSet); ok && parameters.InitialCongestionWindow > 0 {
		t.initialWindow = uint64(parameters.InitialCongestionWindow)
	}
	if packet, ok := event.(qlog.PacketSent); ok {
		for _, frame := range packet.Frames {
			if frequency, ok := frame.Frame.(*qlog.LegacyAckFrequencyFrame); ok {
				t.frames = append(t.frames, *frequency)
				t.packetTypes = append(t.packetTypes, packet.Header.PacketType)
			}
		}
	}
}

func TestQUICPeerAckFrequencyProfilesOverridesAndSnapshots(t *testing.T) {
	for _, mode := range []string{"firefox", "chrome", "peer-disabled", "sender-disabled", "receive-disabled", "custom"} {
		t.Run(mode, func(t *testing.T) {
			minimum := time.Millisecond
			if mode == "peer-disabled" {
				minimum = 0
			}
			peer := newH3PeerWithQPACK(t, nil, func(config *quic.Config) { config.LegacyAckFrequencyMinDelay = minimum })
			profile := surf.NewClient().Builder().Impersonate().Windows()
			var b *surf.Builder
			if mode == "chrome" {
				b = profile.Chrome()
			} else {
				b = profile.Firefox()
			}
			trace := new(peerAckFrequencyClientTrace)
			q := b.ForceHTTP3().QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace })
			if mode == "sender-disabled" {
				q.PeerAckFrequencyPolicy(nil)
			}
			if mode == "receive-disabled" {
				q.LegacyAckFrequency(0)
			}
			if mode == "custom" {
				q.InitialCongestionWindowPackets(16).PeerAckFrequencyPolicy(func(info surf.PeerAckFrequencyInfo) (surf.PeerAckFrequency, bool) {
					target := surf.PeerAckFrequency{AckElicitingThreshold: 12, MaxAckDelay: max(info.PeerMinAckDelay, 2*time.Millisecond), IgnoreOrder: true}
					return target, target != info.Current
				})
			}
			client := q.Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			// Build must freeze callbacks and numeric controls for future dials.
			q.InitialCongestionWindowPackets(1).PeerAckFrequencyPolicy(func(surf.PeerAckFrequencyInfo) (surf.PeerAckFrequency, bool) { return surf.PeerAckFrequency{}, true })
			peer.request(t, client)
			trace.mu.Lock()
			defer trace.mu.Unlock()
			enabled := mode != "chrome" && mode != "peer-disabled" && mode != "sender-disabled"
			if !enabled {
				require.Empty(t, trace.frames)
			} else {
				require.NotEmpty(t, trace.frames)
				require.EqualValues(t, 0, trace.frames[0].SequenceNumber)
				for _, packetType := range trace.packetTypes {
					require.Equal(t, qlog.PacketType1RTT, packetType)
				}
				if mode == "custom" {
					require.EqualValues(t, 12, trace.frames[0].AckElicitingThreshold)
					require.Equal(t, 2*time.Millisecond, trace.frames[0].RequestMaxAckDelay)
					require.True(t, trace.frames[0].IgnoreOrder)
				} else {
					require.EqualValues(t, 2, trace.frames[0].AckElicitingThreshold)
				}
			}
			packets := uint64(10)
			if mode == "chrome" {
				packets = 32
			} else if mode == "custom" {
				packets = 16
			}
			peer.packet.mu.Lock()
			initialSize := peer.packet.initials[0].size
			peer.packet.mu.Unlock()
			require.EqualValues(t, packets*uint64(initialSize), trace.initialWindow)
		})
	}
}

func TestQUICInitialCongestionWindowValidation(t *testing.T) {
	for _, packets := range []uint32{1, 10001} {
		result := surf.NewClient().Builder().ForceHTTP3().QUICSettings().InitialCongestionWindowPackets(packets).Set().Build()
		require.True(t, result.IsErr())
		require.ErrorContains(t, result.Err(), "congestion window")
	}
}
