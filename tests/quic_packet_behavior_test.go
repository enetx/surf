package surf_test

import (
	"testing"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestQUICPacketBehaviorValidationAndClone(t *testing.T) {
	for _, apply := range []func(*surf.QUICSettings){
		func(q *surf.QUICSettings) { q.ReceiveWindowUpdateDivisor(1) },
		func(q *surf.QUICSettings) { q.InitialPaddingMode(255) },
		func(q *surf.QUICSettings) { q.AckOnlyPingThreshold(-2) },
		func(q *surf.QUICSettings) { q.AckOnlyMaxDataThreshold(-1) },
		func(q *surf.QUICSettings) { q.InitialCryptoFrameSplits(-1, 10) },
		func(q *surf.QUICSettings) { q.InitialCryptoFrameSplits(10, 2) },
		func(q *surf.QUICSettings) { q.InitialPingFrames(0, 65) },
		func(q *surf.QUICSettings) { q.InitialCryptoFirstFrameSize(55, 16385) },
		func(q *surf.QUICSettings) { q.InitialCryptoFirstFrameSize(0, 86) },
	} {
		q := surf.NewClient().Builder().ForceHTTP3().QUICSettings()
		apply(q)
		require.True(t, q.Set().Build().IsErr())
	}
	policy := &quic.InitialPacketProtection{MinCryptoSplits: 2, MaxCryptoSplits: 10}
	config := &quic.Config{ClientHandshake: &quic.ClientHandshake{InitialPacketProtection: policy}}
	clone := config.Clone()
	policy.MaxCryptoSplits = 64
	require.Equal(t, 10, clone.ClientHandshake.InitialPacketProtection.MaxCryptoSplits)
	clone.ClientHandshake.InitialPacketProtection.MinCryptoSplits = 4
	require.Equal(t, 2, policy.MinCryptoSplits)
	client := surf.NewClient().Builder().Impersonate().Chrome().QUICSettings().
		InitialCryptoFrameSplits(1, 1).InitialPingFrames(0, 0).
		ResetInitialPacketProtection().Set().Build().Unwrap()
	client.Close()
}
