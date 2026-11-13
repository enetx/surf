package surf_test

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

type earlyHintUDP struct {
	net.PacketConn
	holdInitial atomic.Bool
	dropped     atomic.Int32
}

func (c *earlyHintUDP) WriteTo(data []byte, addr net.Addr) (int, error) {
	originalLength := len(data)
	for c.holdInitial.Load() && isH3Initial(data) {
		// Preserve any coalesced Handshake packet unchanged. Otherwise a small
		// resumed server flight can lose both levels and produce no peer hint.
		pos := 5
		for range 2 {
			if pos >= len(data) || pos+1+int(data[pos]) > len(data) {
				return 0, io.ErrUnexpectedEOF
			}
			pos += 1 + int(data[pos])
		}
		token, consumed, err := quicvarint.Parse(data[pos:])
		if err != nil || token > uint64(len(data)-pos-consumed) {
			return 0, io.ErrUnexpectedEOF
		}
		pos += consumed + int(token)
		length, consumed, err := quicvarint.Parse(data[pos:])
		if err != nil || length > uint64(len(data)-pos-consumed) {
			return 0, io.ErrUnexpectedEOF
		}
		data = data[pos+consumed+int(length):]
		c.dropped.Add(1)
	}
	if len(data) > 0 {
		if _, err := c.PacketConn.WriteTo(data, addr); err != nil {
			return 0, err
		}
	}
	return originalLength, nil
}

type earlyHintTrace struct {
	mutex           sync.Mutex
	pto             bool
	hints           int
	initialRTT      time.Duration
	copiesBeforePTO int
	ranges          []qlog.StreamFrame
	selected        bool
	enabled         bool
	releaseInitial  func()
}

func (r *earlyHintTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *earlyHintTrace) Close() error                     { return nil }
func (r *earlyHintTrace) RecordEvent(event qlogwriter.Event) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	switch e := event.(type) {
	case qlog.RecoveryParametersSet:
		if r.initialRTT == 0 {
			r.initialRTT = e.InitialRTT
		}
	case qlog.TimerUpdated:
		if e.Type == qlog.TimerEventTypeExpired && e.TimerType == qlog.TimerTypePTO {
			r.pto = true
			r.releaseInitial()
			if !r.enabled {
				r.selected = true
			}
		}
	case qlog.PacketSent:
		if e.Header.PacketType != qlog.PacketType0RTT || r.pto {
			return
		}
		for _, frame := range e.Frames {
			stream, ok := frame.Frame.(*qlog.StreamFrame)
			if !ok || stream.Length == 0 {
				continue
			}
			for _, old := range r.ranges {
				if old.StreamID == stream.StreamID && old.Offset < stream.Offset+stream.Length && stream.Offset < old.Offset+old.Length {
					r.copiesBeforePTO++
					r.selected = true
					r.releaseInitial()
					break
				}
			}
			r.ranges = append(r.ranges, *stream)
		}
	}
}

func TestFirefoxPeerHintRepeatsEarlySTREAMBeforePTOOnWire(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit-disable", true: "profile"}[enabled], func(t *testing.T) {
			var packet *earlyHintUDP
			peer := newRestartPeer(t, "accept", func(conn net.PacketConn) net.PacketConn {
				packet = &earlyHintUDP{PacketConn: conn}
				return packet
			})
			peer.disableEarlyPeerRecovery = !enabled
			// A loopback RTT learned during warm-up can be shorter than race
			// instrumentation scheduling. Isolate hint selection from PTO timing.
			peer.earlyHintRTT = 300 * time.Millisecond
			client := restartClient(t, peer, true)
			close(peer.release)
			trace := &earlyHintTrace{enabled: enabled, releaseInitial: func() { packet.holdInitial.Store(false) }}
			peer.additionalTrace = trace
			peer.earlyHintObserver = func(quic.PeerPacketInfo) {
				trace.mutex.Lock()
				trace.hints++
				trace.mutex.Unlock()
			}
			packet.holdInitial.Store(true)
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, peer.url+"/early-hint", nil)
			require.NoError(t, err)
			response, err := client.GetClient().Do(request)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			require.NoError(t, err)
			require.NotEmpty(t, response.TLS.VerifiedChains)
			seen := <-peer.seen
			require.True(t, seen.resumed)
			require.True(t, seen.early)
			require.EqualValues(t, 2, seen.connection)
			trace.mutex.Lock()
			defer trace.mutex.Unlock()
			require.Equal(t, peer.earlyHintRTT, trace.initialRTT)
			require.Positive(t, trace.hints)
			require.True(t, trace.selected, "hints=%d dropped=%d ranges=%v", trace.hints, packet.dropped.Load(), trace.ranges)
			if enabled {
				require.Positive(t, trace.copiesBeforePTO)
			} else {
				require.Zero(t, trace.copiesBeforePTO)
			}
		})
	}
}
