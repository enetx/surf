package surf_test

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestQUICCongestionControlFluentSnapshot(t *testing.T) {
	for _, algorithm := range []surf.CongestionControlAlgorithm{surf.CongestionControlNative, surf.CongestionControlReno, surf.CongestionControlCubic, surf.CongestionControlCubicBytes} {
		for _, slow := range []surf.SlowStartAlgorithm{surf.SlowStartNative, surf.SlowStartClassic, surf.SlowStartHybrid} {
			peer := newH3Peer(t)
			trace := new(peerAckFrequencyClientTrace)
			q := surf.NewClient().Builder().ForceHTTP3().QUICSettings().
				CongestionControl(algorithm).SlowStart(slow).
				CongestionControlSegmentSize(1460).CongestionControlConnections(1).
				InitialCongestionWindowPackets(12).
				Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace })
			client := q.Set().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			q.CongestionControl(255).SlowStart(255).CongestionControlSegmentSize(1).CongestionControlConnections(100)
			peer.request(t, client)
			trace.mu.Lock()
			window := trace.initialWindow
			trace.mu.Unlock()
			require.EqualValues(t, 12*1460, window)
		}
	}
}

func TestQUICCongestionControlRejectsInvalidOptions(t *testing.T) {
	for _, configure := range []func(*surf.QUICSettings){
		func(q *surf.QUICSettings) { q.CongestionControl(255) },
		func(q *surf.QUICSettings) { q.SlowStart(255) },
		func(q *surf.QUICSettings) { q.CongestionControlSegmentSize(1199) },
		func(q *surf.QUICSettings) { q.CongestionControlSegmentSize(65528) },
		func(q *surf.QUICSettings) { q.CongestionControlConnections(17) },
		func(q *surf.QUICSettings) {
			q.CongestionControl(surf.CongestionControlCubic).CongestionControlConnections(2)
		},
	} {
		q := surf.NewClient().Builder().ForceHTTP3().QUICSettings()
		configure(q)
		result := q.Set().Build()
		require.True(t, result.IsErr())
	}
}
