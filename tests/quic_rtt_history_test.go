package surf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
	"github.com/wzshiming/socks5"
)

func TestQUICCachedInitialRTTOnWire(t *testing.T) {
	for _, mode := range []string{"chrome", "firefox", "custom", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			peer := newH3Peer(t)
			builder := surf.NewClient().Builder()
			switch mode {
			case "chrome", "disabled":
				builder.Impersonate().Chrome()
			case "firefox":
				builder.Impersonate().Firefox()
			}
			ready := make(chan *quic.Conn, 4)
			q := builder.QUICSettings().OnApplicationReady(func(c *quic.Conn) { ready <- c })
			if mode == "custom" {
				q.CachedInitialRTT(0x3127, 10*time.Millisecond, time.Second)
			}
			if mode == "disabled" {
				q.CachedInitialRTT(0, 0, 0)
			}
			client := q.Set().ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			var previous time.Duration
			for attempt := 0; attempt < 3; attempt++ {
				peer.request(t, client)
				conn := <-ready
				_, values, _ := quicWireParameters(t, peer)
				if attempt == 0 || mode == "firefox" || mode == "disabled" {
					require.NotContains(t, values, uint64(0x3127), "cold/disabled RTT must not be fabricated")
				} else {
					requireQUICParameter(t, values, 0x3127, uint64(previous.Microseconds()))
				}
				client.CloseIdleConnections()
				stats := conn.ConnectionStats()
				require.True(t, stats.RTTMeasured, "need an actual ACK measurement")
				previous = stats.SmoothedRTT.Truncate(time.Microsecond)
				peer.packet.mu.Lock()
				peer.packet.rawInitials = nil
				peer.packet.initials = nil
				peer.packet.mu.Unlock()
			}
		})
	}
}

func TestQUICCachedInitialRTTProxyIsolation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	proxy := socks5.NewServer()
	proxy.Context = t.Context()
	proxy.ProxyListenPacket = func(context.Context, string, string) (net.PacketConn, error) {
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}
	go proxy.Serve(listener)
	peer := newH3Peer(t)
	client := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP3().Proxy(g.String("socks5://" + listener.Addr().String())).TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	for range 3 {
		peer.request(t, client)
		_, values, _ := quicWireParameters(t, peer)
		require.NotContains(t, values, uint64(0x3127))
		client.CloseIdleConnections()
		resetRTTWireCapture(peer)
	}
}

func resetRTTWireCapture(peer *h3Peer) {
	peer.packet.resetInitials()
}

func TestQUICCaptureResetExcludesLatePriorConnectionInitials(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	capture := &h3CaptureConn{PacketConn: server}
	buffer := make([]byte, 1500)
	// Record the previous server's source CID before resetting the observation.
	_, err = capture.WriteTo([]byte{0xc0, 0, 0, 0, 1, 1, 0xaa, 1, 0xbb}, client.LocalAddr())
	require.NoError(t, err)
	_, _, err = client.ReadFrom(buffer)
	require.NoError(t, err)
	capture.resetInitials()
	for _, cid := range []byte{0xbb, 0xcc} {
		packet := []byte{0xc0, 0, 0, 0, 1, 1, cid, 0}
		_, err = client.WriteTo(packet, server.LocalAddr())
		require.NoError(t, err)
		n, _, err := capture.ReadFrom(buffer)
		require.NoError(t, err)
		require.Equal(t, packet, buffer[:n], "filter only the capture, never the server input")
	}
	require.Len(t, capture.rawInitials, 1)
	require.Equal(t, byte(0xcc), capture.rawInitials[0][6])
}

func TestQUICCachedInitialRTTDoesNotLearnFailedHandshake(t *testing.T) {
	peer := newH3Peer(t)
	var reject atomic.Bool
	reject.Store(true)
	client := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true, VerifyConnection: func(tls.ConnectionState) error {
		if reject.Load() {
			return errors.New("test certificate veto")
		}
		return nil
	}}).Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	failed := client.Get(g.String(peer.url)).Do()
	require.True(t, failed.IsErr())
	client.CloseIdleConnections()
	resetRTTWireCapture(peer)
	reject.Store(false)
	peer.request(t, client)
	_, values, _ := quicWireParameters(t, peer)
	require.NotContains(t, values, uint64(0x3127))
}

func TestQUICCachedInitialRTTClientIsolation(t *testing.T) {
	peer := newH3Peer(t)
	for range 2 {
		client := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
		peer.request(t, client)
		_, values, _ := quicWireParameters(t, peer)
		require.NotContains(t, values, uint64(0x3127))
		client.Close()
		resetRTTWireCapture(peer)
	}
}

func TestQUICCachedInitialRTTValidation(t *testing.T) {
	for _, tc := range []struct {
		id               uint64
		minimum, maximum time.Duration
	}{
		{0x3127, 0, time.Second}, {0x3127, time.Second, time.Millisecond}, {0x3127, time.Millisecond, -1},
		{1, time.Millisecond, time.Second}, {1 << 62, time.Millisecond, time.Second},
	} {
		result := surf.NewClient().Builder().QUICSettings().CachedInitialRTT(tc.id, tc.minimum, tc.maximum).Set().ForceHTTP3().Build()
		require.True(t, result.IsErr())
	}
	result := surf.NewClient().Builder().QUICSettings().InitialRTT(-time.Second).Set().ForceHTTP3().Build()
	require.True(t, result.IsErr())
	result = surf.NewClient().Builder().QUICSettings().InitialPTOMultiplier(17).Set().ForceHTTP3().Build()
	require.True(t, result.IsErr())
}
