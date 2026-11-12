package surf_test

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestQUICLegacyAckFrequencyValidationAndDisable(t *testing.T) {
	for _, delay := range []time.Duration{-time.Millisecond, time.Nanosecond, 21 * time.Millisecond} {
		q := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3().QUICSettings()
		result := q.LegacyAckFrequency(delay).Set().Build()
		require.True(t, result.IsErr())
		require.ErrorContains(t, result.Err(), "ACK_FREQUENCY")
		client := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3().
			QUICSettings().LegacyAckFrequency(delay).LegacyAckFrequency(0).Set().Build().Unwrap()
		client.Close()
	}
}

func TestQUICLegacyAckFrequencyAdvertisementOverrides(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Millisecond, 2 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			peer := newH3Peer(t)
			client := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3().
				QUICSettings().LegacyAckFrequency(delay).
				TransportParameterOrder(0xff02de1a, 15).DisableTransportParameterGrease(true).Set().
				TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			peer.request(t, client)
			hello, _ := h3CapturedHello(t, peer)
			data := h3HelloExtensions(t, hello)[57]
			firstID, _, err := quicvarint.Parse(data)
			require.NoError(t, err)
			if delay > 0 {
				require.EqualValues(t, uint64(0xff02de1a), firstID)
			}
			found := false
			for len(data) > 0 {
				id, n, err := quicvarint.Parse(data)
				require.NoError(t, err)
				data = data[n:]
				size, n, err := quicvarint.Parse(data)
				require.NoError(t, err)
				data = data[n:]
				require.LessOrEqual(t, size, uint64(len(data)))
				if id == 0xff02de1a {
					found = true
					value, consumed, err := quicvarint.Parse(data[:size])
					require.NoError(t, err)
					require.EqualValues(t, size, consumed)
					require.EqualValues(t, delay/time.Microsecond, value)
				}
				data = data[size:]
			}
			require.Equal(t, delay > 0, found)
		})
	}
}
