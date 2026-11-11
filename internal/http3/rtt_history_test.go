package h3transport

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/transportparams"
)

func TestRTTHistoryValueAndLocalClamp(t *testing.T) {
	for _, sample := range []time.Duration{0, -1, time.Nanosecond, 2*time.Millisecond + 999*time.Nanosecond, 50 * time.Millisecond, 3 * time.Second} {
		h := &rttHistory{parameter: 0x3127, minimum: 10 * time.Millisecond, maximum: time.Second,
			entries: map[string]*rttEntry{"origin:443": {sample: func() time.Duration { return sample }}}}
		original := &transportparams.Layout{Order: []uint64{0x3127, 99}, Additional: []transportparams.Parameter{{ID: 99, Value: []byte{7}}, {ID: 0x3127, Value: []byte{1}}}}
		config := &quic.Config{ClientHandshake: &quic.ClientHandshake{NewTransportParameters: func(quic.Version) (*transportparams.Layout, error) { return original, nil }}}
		got, _ := h.prepare("ORIGIN:443", config)
		layout, err := got.ClientHandshake.NewTransportParameters(quic.Version1)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(original.Additional[1].Value, []byte{1}) {
			t.Fatal("mutated caller factory")
		}
		var value []byte
		for _, p := range layout.Additional {
			if p.ID == 0x3127 {
				value = p.Value
			}
		}
		if sample < time.Microsecond {
			if value != nil || got.ClientHandshake.InitialRTT != 0 {
				t.Fatal("advertised an unmeasured/fractional RTT")
			}
		} else {
			n, width, err := quicvarint.Parse(value)
			if err != nil || width != len(value) || n != uint64(sample.Microseconds()) {
				t.Fatal("wire RTT was clamped or encoded incorrectly")
			}
			if got.ClientHandshake.InitialRTT != max(h.minimum, min(h.maximum, sample.Truncate(time.Microsecond))) {
				t.Fatal("local initial RTT was not clamped")
			}
		}
		if config.ClientHandshake.InitialRTT != 0 {
			t.Fatal("mutated shared config")
		}
	}
}

func TestRTTHistoryLifetimeAndErrors(t *testing.T) {
	h := &rttHistory{parameter: 0x3127, minimum: time.Millisecond, maximum: time.Second}
	_, oldFinish := h.prepare("a:443", nil)
	_, newFinish := h.prepare("a:443", nil)
	entry := h.entries["a:443"]
	entry.sample = func() time.Duration { return 20 * time.Millisecond }
	oldFinish(nil, errors.New("stale failure"))
	if entry.sample == nil {
		t.Fatal("older attempt cleared a newer entry")
	}
	newFinish(nil, &net.DNSError{Err: "resolution failed"})
	if entry.sample == nil {
		t.Fatal("DNS failure destroyed earlier connection history")
	}
	_, finish := h.prepare("a:443", nil)
	finish(nil, errors.New("handshake failed"))
	if entry.sample != nil {
		t.Fatal("failed session retained its predecessor")
	}
	_, finish = h.prepare("a:443", nil)
	finish(nil, nil)
	if entry.sample() != 0 {
		t.Fatal("invalid nil connection measurement")
	}
	for n := 0; n < 300; n++ {
		h.prepare(net.JoinHostPort("origin", strconv.Itoa(n+1000)), nil)
	}
	if len(h.entries) != 256 {
		t.Fatalf("unbounded history: %d", len(h.entries))
	}
	h.close()
	finish(nil, nil)
	c, closed := h.prepare("new:443", nil)
	closed(nil, nil)
	if c != nil || len(h.entries) != 0 {
		t.Fatal("closed cache retained new work")
	}
}

func TestRTTHistoryConcurrentOrigins(t *testing.T) {
	h := &rttHistory{parameter: 0x3127, minimum: time.Millisecond, maximum: time.Second}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for range 30 {
				_, finish := h.prepare("a:443", nil)
				finish(nil, nil)
			}
		})
	}
	wg.Wait()
	h.close()
}

func TestRTTHistoryOriginIsolation(t *testing.T) {
	h := &rttHistory{parameter: 0x3127, minimum: time.Millisecond, maximum: time.Second, entries: map[string]*rttEntry{"first:443": {sample: func() time.Duration { return 20 * time.Millisecond }}}}
	for _, origin := range []string{"second:443", "first:8443"} {
		config, _ := h.prepare(origin, nil)
		if config.ClientHandshake.InitialRTT != 0 {
			t.Fatal("RTT crossed origin/port boundaries")
		}
	}
}

func TestRTTHistoryFactoryError(t *testing.T) {
	h := &rttHistory{parameter: 0x3127, minimum: time.Millisecond, maximum: time.Second}
	want := errors.New("factory failed")
	config := &quic.Config{ClientHandshake: &quic.ClientHandshake{NewTransportParameters: func(quic.Version) (*transportparams.Layout, error) { return nil, want }}}
	got, _ := h.prepare("a:443", config)
	if _, err := got.ClientHandshake.NewTransportParameters(quic.Version1); !errors.Is(err, want) {
		t.Fatal("lost factory error")
	}
}
