package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNetworkDelayPipelinesAndPreservesCopiedPayloads(t *testing.T) {
	base, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()
	shaped := newShapedUDP(base, 20*time.Millisecond, 0, 0, nil)
	defer shaped.Close()
	start := time.Now()
	for i := range 3 {
		data := []byte{byte(i)}
		_, err = shaped.WriteTo(data, peer.LocalAddr())
		require.NoError(t, err)
		data[0] = 255
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	for i := range 3 {
		var data [1]byte
		_, _, err := peer.ReadFrom(data[:])
		require.NoError(t, err)
		require.EqualValues(t, i, data[0])
		require.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)
	}
	_, err = peer.WriteTo([]byte("incoming"), shaped.LocalAddr())
	require.NoError(t, err)
	shaped.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 32)
	n, _, err := shaped.ReadFrom(data)
	require.NoError(t, err)
	require.Equal(t, "incoming", string(data[:n]))
}
func TestNetworkLossPerRemoteAndDeadlines(t *testing.T) {
	base, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	shaped := newShapedUDP(base, 0, 2, 0, nil)
	defer shaped.Close()
	for range 2 {
		peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		for i := range 4 {
			_, err = peer.WriteTo([]byte{byte(i)}, shaped.LocalAddr())
			require.NoError(t, err)
		}
		shaped.SetReadDeadline(time.Now().Add(time.Second))
		for _, want := range []byte{0, 2} {
			var data [1]byte
			n, _, err := shaped.ReadFrom(data[:])
			require.NoError(t, err)
			require.Equal(t, 1, n)
			require.Equal(t, want, data[0])
		}
		shaped.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		_, _, err = shaped.ReadFrom(make([]byte, 32))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		shaped.SetDeadline(time.Time{})
		for i := range 4 {
			_, err = shaped.WriteTo([]byte{byte(i)}, peer.LocalAddr())
			require.NoError(t, err)
		}
		peer.SetReadDeadline(time.Now().Add(time.Second))
		for _, want := range []byte{0, 2} {
			var data [1]byte
			_, _, err = peer.ReadFrom(data[:])
			require.NoError(t, err)
			require.Equal(t, want, data[0])
		}
		peer.Close()
	}
	shaped.SetWriteDeadline(time.Now().Add(-time.Second))
	_, err = shaped.WriteTo([]byte("x"), shaped.LocalAddr())
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	shaped.Close()
	_, _, err = shaped.ReadFrom(make([]byte, 32))
	require.True(t, errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded))
	_, err = shaped.WriteTo([]byte("x"), shaped.LocalAddr())
	require.Error(t, err)
}

func TestNetworkFirstDatagramLossIsPerDirection(t *testing.T) {
	base, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()
	shaped := newShapedUDP(base, 0, 0, 1, nil)
	defer shaped.Close()
	for _, value := range []string{"discard", "deliver"} {
		_, err = peer.WriteTo([]byte(value), shaped.LocalAddr())
		require.NoError(t, err)
	}
	shaped.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 64)
	n, _, err := shaped.ReadFrom(data)
	require.NoError(t, err)
	require.Equal(t, "deliver", string(data[:n]))
	for _, value := range []string{"discard", "deliver"} {
		_, err = shaped.WriteTo([]byte(value), peer.LocalAddr())
		require.NoError(t, err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = peer.ReadFrom(data)
	require.NoError(t, err)
	require.Equal(t, "deliver", string(data[:n]))
}
