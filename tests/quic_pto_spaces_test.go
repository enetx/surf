package surf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	firefox "github.com/enetx/surf/profiles/firefox/quic"
	"github.com/stretchr/testify/require"
)

type ptoLossUDP struct {
	net.PacketConn
	mu      sync.Mutex
	space   string
	until   time.Time
	window  time.Duration
	dropped int
}

func (c *ptoLossUDP) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		c.mu.Lock()
		matches := containsPTOEncryptionSpace(b[:n], c.space)
		now := time.Now()
		if matches && c.until.IsZero() {
			c.until = now.Add(c.window)
		}
		drop := matches && now.Before(c.until)
		if drop {
			c.dropped++
		}
		c.mu.Unlock()
		if !drop {
			return n, addr, nil
		}
	}
}

// A datagram may carry Initial, Handshake and Application packets together.
// Classify every protected packet, ignoring negotiated fixed-bit GREASE and
// the zero datagram-padding tail. Dropping its first header alone misses loss.
func containsPTOEncryptionSpace(data []byte, space string) bool {
	for len(data) > 0 {
		if data[0]&0x80 == 0 {
			return space == "application" && bytes.Count(data, []byte{0}) != len(data)
		}
		if len(data) < 7 {
			return false
		}
		version, kind := binary.BigEndian.Uint32(data[1:5]), (data[0]>>4)&3
		initial, early, handshake := byte(0), byte(1), byte(2)
		if version == uint32(quic.Version2) {
			initial, early, handshake = 1, 2, 3
		} else if version != uint32(quic.Version1) {
			return false
		}
		if kind == handshake && space == "handshake" || kind == early && space == "application" {
			return true
		}
		if kind != initial && kind != early && kind != handshake {
			return false
		}
		pos := 5
		for range 2 {
			if pos >= len(data) || pos+1+int(data[pos]) > len(data) {
				return false
			}
			pos += 1 + int(data[pos])
		}
		if kind == initial {
			length, consumed, err := quicvarint.Parse(data[pos:])
			if err != nil || length > uint64(len(data)-pos-consumed) {
				return false
			}
			pos += consumed + int(length)
		}
		length, consumed, err := quicvarint.Parse(data[pos:])
		if err != nil || length > uint64(len(data)-pos-consumed) {
			return false
		}
		data = data[pos+consumed+int(length):]
	}
	return false
}

type ptoSpaceTrace struct {
	mu       sync.Mutex
	separate bool
	last     map[qlog.PacketType]int64
	any      int64
	pending  *struct {
		kind     qlog.PacketType
		previous int64
	}
	gaps []struct {
		kind qlog.PacketType
		gap  int64
	}
}

func (r *ptoSpaceTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *ptoSpaceTrace) Close() error                     { return nil }
func (r *ptoSpaceTrace) RecordEvent(event qlogwriter.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch e := event.(type) {
	case qlog.TimerUpdated:
		if e.Type != qlog.TimerEventTypeExpired || e.TimerType != qlog.TimerTypePTO {
			return
		}
		var kind qlog.PacketType
		switch e.EncLevel.String() {
		case "Handshake":
			kind = qlog.PacketTypeHandshake
		case "1-RTT":
			kind = qlog.PacketType1RTT
		default:
			return
		}
		previous := r.any
		if r.separate {
			previous = r.last[kind]
		}
		r.pending = &struct {
			kind     qlog.PacketType
			previous int64
		}{kind, previous}
	case qlog.PacketSent:
		if r.pending != nil && (e.Header.PacketType == r.pending.kind || !r.separate) {
			r.gaps = append(r.gaps, struct {
				kind qlog.PacketType
				gap  int64
			}{r.pending.kind, int64(e.Header.PacketNumber) - r.pending.previous})
			r.pending = nil
		}
		r.last[e.Header.PacketType] = int64(e.Header.PacketNumber)
		r.any = int64(e.Header.PacketNumber)
	}
}

func TestBrowserHandshakeAndApplicationPTOOnWire(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		for _, space := range []string{"handshake", "application"} {
			t.Run(browser+"/"+space, func(t *testing.T) {
				var loss *ptoLossUDP
				peer := newDiscoveryPeer(t, nil, func(conn net.PacketConn) net.PacketConn { loss = &ptoLossUDP{PacketConn: conn}; return loss })
				trace := &ptoSpaceTrace{last: make(map[qlog.PacketType]int64), separate: browser == "firefox"}
				builder := discoveryBuilder(browser).ForceHTTP3().Proxy("").TLSConfig(&tls.Config{RootCAs: peer.roots}).Timeout(8 * time.Second)
				builder.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }).Set()
				client := builder.Build().Unwrap()
				t.Cleanup(func() { client.Close() })
				// Changing the builder cannot change the published client's PTO gap.
				builder.QUICSettings().ApplicationProbeSkipPacketNumber(browser != "chrome").Set()
				if space == "application" {
					request, err := http.NewRequest(http.MethodGet, peer.tcp.URL, nil)
					require.NoError(t, err)
					response, err := client.GetClient().Do(request)
					require.NoError(t, err)
					_, err = io.Copy(io.Discard, response.Body)
					response.Body.Close()
					require.NoError(t, err)
				}
				loss.mu.Lock()
				loss.space = space
				loss.window = 180 * time.Millisecond
				loss.until = time.Time{}
				loss.mu.Unlock()
				payload := strings.Repeat("PTO regression payload\x00", 4096)
				request, err := http.NewRequest(http.MethodPost, peer.tcp.URL, strings.NewReader(payload))
				require.NoError(t, err)
				response, err := client.GetClient().Do(request)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				require.NoError(t, err)
				require.Equal(t, payload+"ok", string(body))
				require.Equal(t, 3, response.ProtoMajor)
				require.NotEmpty(t, response.TLS.VerifiedChains)
				loss.mu.Lock()
				dropped := loss.dropped
				loss.mu.Unlock()
				require.Positive(t, dropped)
				trace.mu.Lock()
				defer trace.mu.Unlock()
				kind := qlog.PacketTypeHandshake
				if space == "application" {
					kind = qlog.PacketType1RTT
				}
				found := false
				for _, sample := range trace.gaps {
					if sample.kind != kind {
						continue
					}
					found = true
					if browser == "firefox" {
						require.EqualValues(t, 1, sample.gap)
					} else {
						require.GreaterOrEqual(t, sample.gap, int64(2))
					}
				}
				require.True(t, found, "loss must exercise a real %s PTO; observed %v", space, trace.gaps)
			})
		}
	}
}

func TestPeerRecoveryAndPTOFluentControls(t *testing.T) {
	for _, configure := range []func(*surf.QUICSettings){func(q *surf.QUICSettings) { q.HandshakeProbePackets(3) }, func(q *surf.QUICSettings) { q.ApplicationProbePackets(3) }} {
		q := surf.NewClient().Builder().ForceHTTP3().QUICSettings()
		configure(q)
		require.True(t, q.Set().Build().IsErr())
	}
	for _, kind := range []qlog.PacketType{qlog.PacketTypeInitial, qlog.PacketTypeHandshake, qlog.PacketType1RTT} {
		for _, count := range []int{0, 3, 4, 5} {
			info := quic.PeerPacketInfo{PacketType: kind, BufferedHandshakePackets: count}
			action := firefox.PeerRecovery(info)
			require.Equal(t, kind != qlog.PacketTypeInitial && count < 4, action.ResendInitialCrypto, fmt.Sprint(info))
			require.Equal(t, action.ResendInitialCrypto, action.ResendEarlyData)
			info.BufferedHandshakePackets = 0
			info.BufferedApplicationPackets = count
			require.Equal(t, action, firefox.PeerRecovery(info))
			info.HandshakeComplete = true
			require.Equal(t, quic.PeerPacketRecovery{}, firefox.PeerRecovery(info))
		}
	}
	for _, kind := range []qlog.PacketType{qlog.PacketTypeInitial, qlog.PacketTypeHandshake, qlog.PacketType1RTT} {
		require.Equal(t, quic.PeerPacketRecovery{ProbeHandshake: kind == qlog.PacketTypeInitial}, firefox.PeerRecovery(quic.PeerPacketInfo{PacketType: kind, KeysDropped: true}))
		require.Equal(t, quic.PeerPacketRecovery{}, firefox.PeerRecovery(quic.PeerPacketInfo{PacketType: kind, ReceivedFirstPacket: true}))
	}
	client := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3().QUICSettings().HandshakeCryptoResendOnPeerProbe(true).HandshakeCryptoRecovery(false).
		HandshakeProbePackets(0).ApplicationProbePackets(0).HandshakeProbeSkipPacketNumber(false).HandshakeProbeOnlyWithData(false).ImmediateACKOnPeerPing(false).PeerPacketRecoveryPolicy(nil).Set().Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	newH3Peer(t).request(t, client)
}

type missingServerInitialUDP struct {
	net.PacketConn
	dropped      atomic.Bool
	sawHandshake atomic.Bool
}

func (c *missingServerInitialUDP) WriteTo(data []byte, addr net.Addr) (int, error) {
	// An ACK-only Initial may precede ServerHello. Keep dropping Initials
	// until an independent Handshake datagram can expose the missing keys.
	if isH3Initial(data) && !c.sawHandshake.Load() {
		c.dropped.Store(true)
		return len(data), nil
	}
	if len(data) >= 5 && data[0]&0x80 != 0 {
		kind := (data[0] >> 4) & 3
		version := binary.BigEndian.Uint32(data[1:5])
		if version == uint32(quic.Version1) && kind == 2 || version == uint32(quic.Version2) && kind == 3 {
			c.sawHandshake.Store(true)
		}
	}
	return c.PacketConn.WriteTo(data, addr)
}

func TestFirefoxMissingInitialPeerHintOnWire(t *testing.T) {
	var packet *missingServerInitialUDP
	peer := newDiscoveryPeer(t, nil, func(conn net.PacketConn) net.PacketConn {
		packet = &missingServerInitialUDP{PacketConn: conn}
		return packet
	})
	var hints atomic.Int32
	client := discoveryBuilder("firefox").ForceHTTP3().Proxy("").TLSConfig(&tls.Config{RootCAs: peer.roots}).Timeout(8 * time.Second).
		QUICSettings().PeerPacketRecoveryPolicy(func(info quic.PeerPacketInfo) quic.PeerPacketRecovery {
		action := firefox.PeerRecovery(info)
		if action.ResendInitialCrypto {
			hints.Add(1)
		}
		return action
	}).Set().Build().Unwrap()
	t.Cleanup(func() { client.Close() })
	request, err := http.NewRequest(http.MethodGet, peer.tcp.URL, nil)
	require.NoError(t, err)
	response, err := client.GetClient().Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "ok", string(body))
	require.True(t, packet.dropped.Load())
	require.Positive(t, hints.Load())
	require.NotEmpty(t, response.TLS.VerifiedChains)
}
