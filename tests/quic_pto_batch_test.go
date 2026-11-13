package surf_test

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

type pairedRestartTrace struct{ primary, additional qlogwriter.Trace }

func (r *pairedRestartTrace) AddProducer() qlogwriter.Recorder {
	return &pairedRestartRecorder{primary: r.primary.AddProducer(), additional: r.additional.AddProducer()}
}

type pairedRestartRecorder struct{ primary, additional qlogwriter.Recorder }

func (r *pairedRestartRecorder) Close() error {
	return errors.Join(r.primary.Close(), r.additional.Close())
}
func (r *pairedRestartRecorder) RecordEvent(e qlogwriter.Event) {
	r.primary.RecordEvent(e)
	r.additional.RecordEvent(e)
}

type ptoBatchTrace struct {
	mutex                      sync.Mutex
	active, stopped            bool
	datagrams                  map[qlog.DatagramPayloadChecksum]map[qlog.PacketType]bool
	initial, coalesced         chan struct{}
	initialOnce, coalescedOnce sync.Once
}

func (r *ptoBatchTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *ptoBatchTrace) Close() error                     { return nil }
func (r *ptoBatchTrace) RecordEvent(event qlogwriter.Event) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	switch e := event.(type) {
	case qlog.TimerUpdated:
		if e.Type == qlog.TimerEventTypeExpired && e.TimerType == qlog.TimerTypePTO {
			r.active = true
		}
	case qlog.PacketSent:
		if !r.active || r.stopped || e.DatagramPayloadChecksum == 0 {
			return
		}
		if e.Header.PacketType != qlog.PacketTypeInitial && e.Header.PacketType != qlog.PacketType0RTT {
			return
		}
		kinds := r.datagrams[e.DatagramPayloadChecksum]
		if kinds == nil {
			kinds = make(map[qlog.PacketType]bool)
			r.datagrams[e.DatagramPayloadChecksum] = kinds
		}
		kinds[e.Header.PacketType] = true
		if e.Header.PacketType == qlog.PacketTypeInitial {
			r.initialOnce.Do(func() { close(r.initial) })
		}
		if kinds[qlog.PacketTypeInitial] && kinds[qlog.PacketType0RTT] {
			r.coalescedOnce.Do(func() { close(r.coalesced) })
		}
	}
}

func TestFirefoxPTOCoalescesInitialAndEarlyApplicationOnWire(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit-disable", true: "profile"}[enabled], func(t *testing.T) {
			peer := newRestartPeer(t, "accept")
			trace := &ptoBatchTrace{datagrams: make(map[qlog.DatagramPayloadChecksum]map[qlog.PacketType]bool), initial: make(chan struct{}), coalesced: make(chan struct{})}
			peer.disableProbeCoalescing = !enabled
			client := restartClient(t, peer, true)
			// Observe the resumed connection only. A slow ticket warm-up may have
			// its own PTO and must not consume this connection's measured budget.
			peer.additionalTrace = trace
			release := sync.OnceFunc(func() { close(peer.release) })
			t.Cleanup(release)
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, peer.url+"/batch", nil)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() {
				response, err := client.GetClient().Do(request)
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
				done <- err
			}()
			wait := trace.initial
			if enabled {
				wait = trace.coalesced
			}
			select {
			case <-wait:
			case <-time.After(5 * time.Second):
				t.Fatal("missing selected PTO datagram")
			}
			trace.mutex.Lock()
			trace.stopped = true
			initialDatagrams := 0
			combined := false
			for _, kinds := range trace.datagrams {
				if kinds[qlog.PacketTypeInitial] {
					initialDatagrams++
				}
				combined = combined || kinds[qlog.PacketTypeInitial] && kinds[qlog.PacketType0RTT]
			}
			trace.mutex.Unlock()
			require.Equal(t, enabled, combined)
			// Fresh application writes may follow the probes before this goroutine
			// wakes up. Only Initial-bearing datagrams identify this CRYPTO PTO;
			// the handler tests independently count the entire probe allowance.
			require.LessOrEqual(t, initialDatagrams, 2, "PTO must share one two-datagram allowance")
			release()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("request did not complete after PTO")
			}
			seen := <-peer.seen
			require.True(t, seen.resumed)
			require.True(t, seen.early)
			require.EqualValues(t, 2, seen.connection)
		})
	}
}
