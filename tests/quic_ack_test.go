package surf_test

import (
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestQUICAckFluentValidationAndReset(t *testing.T) {
	for _, configure := range []func(*surf.QUICSettings){
		func(q *surf.QUICSettings) { q.AckPacketThreshold(1 << 62) },
		func(q *surf.QUICSettings) { q.AckDecimation(1<<62, 10) },
		func(q *surf.QUICSettings) { q.AckDecimation(100, 1<<62) },
		func(q *surf.QUICSettings) { q.MinAckDelay(-time.Nanosecond) },
		func(q *surf.QUICSettings) { q.MaxAckDelay(5 * time.Millisecond).MinAckDelay(6 * time.Millisecond) },
		func(q *surf.QUICSettings) { q.AckReordering(99) },
		func(q *surf.QUICSettings) { q.AckECN(99) },
		func(q *surf.QUICSettings) { q.AckReordering(surf.AckReorderingWindow) },
	} {
		q := surf.NewClient().Builder().ForceHTTP3().QUICSettings()
		configure(q)
		result := q.Set().Build()
		require.True(t, result.IsErr())
		require.ErrorContains(t, result.Err(), "ACK")
		q.ResetAckPolicy()
		client := q.Set().Build().Unwrap()
		client.Close()
	}
	client := surf.NewClient().Builder().Impersonate().Chrome().QUICSettings().
		AckFlushOnPacket(true).AckPacketThreshold(3).AckDecimation(40, 6).AckDelayRTTDivisor(8).
		MinAckDelay(time.Millisecond).AckReordering(surf.AckReorderingWindow).
		AckMissingPacketLimit(2).AckECN(surf.AckECNTransitions).Set().Build().Unwrap()
	client.Close()
}

func TestQUICAckClientHandshakeClone(t *testing.T) {
	config := &quic.Config{ClientHandshake: &quic.ClientHandshake{AckPolicy: &quic.AckPolicy{FlushOnPacket: true, PacketThreshold: 2, DecimationThreshold: 10, DecimationAfter: 100}}}
	copy := config.Clone()
	config.ClientHandshake.AckPolicy.PacketThreshold = 99
	require.EqualValues(t, 2, copy.ClientHandshake.AckPolicy.PacketThreshold)
	config.ClientHandshake.AckPolicy.FlushOnPacket = false
	require.True(t, copy.ClientHandshake.AckPolicy.FlushOnPacket)
	copy.ClientHandshake.AckPolicy.DecimationAfter = 50
	require.EqualValues(t, 100, config.ClientHandshake.AckPolicy.DecimationAfter)
}
