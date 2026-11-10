package main

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNetworkReordersBothDirectionsAndClosesPending(t *testing.T) {
	base, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()
	shaped := newShapedUDP(base, 0, 0, 0, nil, networkOptions{ReorderEvery: 2, ReorderDelay: 30 * time.Millisecond})
	defer shaped.Close()
	for _, outgoing := range []bool{false, true} {
		for i := byte(1); i <= 3; i++ {
			if outgoing {
				_, err = shaped.WriteTo([]byte{i}, peer.LocalAddr())
			} else {
				_, err = peer.WriteTo([]byte{i}, shaped.LocalAddr())
			}
			require.NoError(t, err)
		}
		var received net.PacketConn = shaped
		if outgoing {
			received = peer
		}
		require.NoError(t, received.SetReadDeadline(time.Now().Add(time.Second)))
		for _, want := range []byte{1, 3, 2} {
			var b [1]byte
			_, _, err := received.ReadFrom(b[:])
			require.NoError(t, err)
			require.Equal(t, want, b[0])
		}
	}
	shaped.mu.Lock()
	for _, flow := range shaped.flows {
		require.EqualValues(t, 1, flow.Reordered)
	}
	shaped.mu.Unlock()
	// A future timer must not retain the scheduler during Close.
	_, err = shaped.WriteTo([]byte{4}, peer.LocalAddr())
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { shaped.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending reorder timer prevented Close")
	}
}

func TestNetworkJitterIsBoundedAndRepeatsPerFlow(t *testing.T) {
	options := networkOptions{Jitter: 5 * time.Millisecond}
	c := &shapedUDP{delay: 10 * time.Millisecond, options: options, flows: make(map[string]*networkFlow)}
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	second := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1001}
	var delays []time.Duration
	for range 20 {
		p, dropped := c.packet([]byte("a"), first, "incoming")
		require.False(t, dropped)
		require.GreaterOrEqual(t, p.delay, 5*time.Millisecond)
		require.LessOrEqual(t, p.delay, 15*time.Millisecond)
		delays = append(delays, p.delay)
	}
	for _, want := range delays {
		p, _ := c.packet([]byte("b"), second, "incoming")
		require.Equal(t, want, p.delay, "fresh remotes start the same reproducible jitter sequence")
	}
	require.NotEqual(t, delays[0], delays[1])
}
