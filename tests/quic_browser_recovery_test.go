package surf_test

import (
	"context"
	"crypto/tls"
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
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type lossTestUDP struct {
	net.PacketConn
	reads, writes, dropped atomic.Int64
}

func (c *lossTestUDP) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		n, address, err := c.PacketConn.ReadFrom(data)
		if err != nil {
			return n, address, err
		}
		if count := c.reads.Add(1); count > 8 && count%17 == 0 {
			c.dropped.Add(1)
			continue
		}
		return n, address, nil
	}
}
func (c *lossTestUDP) WriteTo(data []byte, address net.Addr) (int, error) {
	if count := c.writes.Add(1); count > 8 && count%13 == 0 {
		c.dropped.Add(1)
		return len(data), nil
	}
	return c.PacketConn.WriteTo(data, address)
}

type browserRecoveryTrace struct {
	mu                 sync.Mutex
	first              map[qlog.PacketType]int64
	applicationNumbers []int64
	lost               int
	maxWindow          int
}

func (r *browserRecoveryTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *browserRecoveryTrace) Close() error                     { return nil }
func (r *browserRecoveryTrace) RecordEvent(event qlogwriter.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch e := event.(type) {
	case qlog.PacketSent:
		if e.Header.PacketType == qlog.PacketType1RTT {
			r.applicationNumbers = append(r.applicationNumbers, int64(e.Header.PacketNumber))
		}
		if _, ok := r.first[e.Header.PacketType]; !ok {
			r.first[e.Header.PacketType] = int64(e.Header.PacketNumber)
		}
	case qlog.PacketLost:
		r.lost++
	case qlog.MetricsUpdated:
		r.maxWindow = max(r.maxWindow, e.CongestionWindow)
	}
}

func TestQUICBrowserRecoveryUnderBidirectionalLoss(t *testing.T) {
	for _, browser := range []string{"chrome", "firefox"} {
		t.Run(browser, func(t *testing.T) {
			var lossy *lossTestUDP
			p := newDiscoveryPeer(t, nil, func(conn net.PacketConn) net.PacketConn { lossy = &lossTestUDP{PacketConn: conn}; return lossy })
			trace := &browserRecoveryTrace{first: make(map[qlog.PacketType]int64)}
			q := discoveryBuilder(browser).ForceHTTP3().QUICSettings().InitialPacketNumber(37).
				Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace })
			client := q.Set().TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(15 * time.Second).Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			// Mutating the builder cannot change the sender or PN policy in Build's snapshot.
			q.Pacing(255).MaxCongestionWindowPackets(1).SeparatePacketNumberSpaces(browser != "firefox")
			payload := strings.Repeat("browser recovery payload\x00", 32768)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tcp.URL, strings.NewReader(payload))
			require.NoError(t, err)
			response, err := client.GetClient().Do(request)
			require.NoError(t, err)
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			require.NoError(t, err)
			require.Equal(t, payload+"ok", string(data))
			require.Equal(t, 3, response.ProtoMajor)
			require.Greater(t, lossy.dropped.Load(), int64(0))
			trace.mu.Lock()
			defer trace.mu.Unlock()
			require.Greater(t, trace.lost, 0)
			require.Positive(t, trace.maxWindow)
			for _, kind := range []qlog.PacketType{qlog.PacketTypeInitial, qlog.PacketTypeHandshake, qlog.PacketType1RTT} {
				require.Contains(t, trace.first, kind)
			}
			require.EqualValues(t, 37, trace.first[qlog.PacketTypeInitial])
			if browser == "firefox" {
				require.EqualValues(t, 0, trace.first[qlog.PacketTypeHandshake])
				require.EqualValues(t, 0, trace.first[qlog.PacketType1RTT])
				for i, pn := range trace.applicationNumbers {
					require.EqualValues(t, i, pn, "no artificial skips under loss or PTO")
				}
			} else {
				require.Greater(t, trace.first[qlog.PacketTypeHandshake], int64(37))
				require.Greater(t, trace.first[qlog.PacketType1RTT], trace.first[qlog.PacketTypeHandshake])
				require.LessOrEqual(t, trace.maxWindow, 2000*1460)
			}
		})
	}
}

func TestQUICPacingValidation(t *testing.T) {
	for _, configure := range []func(*surf.QUICSettings){
		func(q *surf.QUICSettings) { q.Pacing(255) },
		func(q *surf.QUICSettings) { q.Pacing(surf.PacingScheduled).PacingBurstPackets(0) },
		func(q *surf.QUICSettings) { q.Pacing(surf.PacingLeakyBucket).PacingGains(0, 2000) },
		func(q *surf.QUICSettings) { q.Pacing(surf.PacingLeakyBucket).PacingGains(2000, 10001) },
		func(q *surf.QUICSettings) { q.Pacing(surf.PacingScheduled).PacingGranularity(-1) },
		func(q *surf.QUICSettings) { q.Pacing(surf.PacingScheduled).PacingLumpyBurst(2, 1001, 0) },
		func(q *surf.QUICSettings) { q.MaxCongestionWindowPackets(-2) },
		func(q *surf.QUICSettings) { q.MaxCongestionWindowPackets(1) },
		func(q *surf.QUICSettings) { q.MaxCongestionWindowPackets(1 << 32) },
		func(q *surf.QUICSettings) { q.MaxCongestionWindowPackets(10).InitialCongestionWindowPackets(11) },
		func(q *surf.QUICSettings) { q.PersistentCongestionThreshold(17) },
		func(q *surf.QUICSettings) { q.RecoveryBurstPackets(17) },
	} {
		q := surf.NewClient().Builder().ForceHTTP3().QUICSettings()
		configure(q)
		require.True(t, q.Set().Build().IsErr())
	}
}
