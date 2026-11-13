package surf_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	h3qlog "github.com/enetx/quic-go/http3/qlog"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type earlySettingsPacket struct{ streams []qlog.StreamFrame }

func assertFinishedHeadersFIN(t *testing.T, frames []qlog.StreamFrame) {
	t.Helper()
	var end, finEnd int64
	var seenFIN bool
	for _, frame := range frames {
		end = max(end, frame.Offset+frame.Length)
		if frame.Fin {
			if !seenFIN {
				require.Positive(t, frame.Length, "the first FIN must accompany HEADERS bytes")
				finEnd = frame.Offset + frame.Length
			} else {
				require.Equal(t, finEnd, frame.Offset+frame.Length, "retransmitted FIN changed final size")
			}
			seenFIN = true
		}
	}
	require.True(t, seenFIN, "HEADERS did not close the bodyless request")
	require.Equal(t, end, finEnd, "FIN did not accompany the last HEADERS byte")
}

// Neqo's DataSent bytes are eligible in its higher retransmission class.
// Previously sent critical ranges can precede the request in that same class;
// ordinary new critical bytes must follow. Earlier setup-only packets remain
// legitimate when the application had not queued its request yet.
func assertEarlyFinishedStreamOrder(t *testing.T, packets []earlySettingsPacket, request quic.StreamID) {
	t.Helper()
	seen := make(map[quic.StreamID]int64)
	for _, packet := range packets {
		requestAt := -1
		for i, stream := range packet.streams {
			if stream.StreamID == request && stream.Length > 0 {
				requestAt = i
				break
			}
		}
		for i, stream := range packet.streams {
			if requestAt >= 0 && stream.StreamID != request && stream.Length > 0 &&
				stream.Offset+stream.Length > seen[stream.StreamID] {
				require.Less(t, requestAt, i, "new stream %d passed finished request %d", stream.StreamID, request)
			}
			seen[stream.StreamID] = max(seen[stream.StreamID], stream.Offset+stream.Length)
		}
	}
}

type earlySettingsTrace struct {
	mu                  sync.Mutex
	packets             []earlySettingsPacket
	requestSent         chan struct{}
	once                sync.Once
	settingsCreated     bool
	initialRanges       [][2]int64
	initialDatagrams    map[qlog.DatagramPayloadChecksum]bool
	firstEarlyComplete  bool
	firstEarlyCoalesced bool
	requestFrames       []qlog.StreamFrame
}

func (t *earlySettingsTrace) AddProducer() qlogwriter.Recorder { return t }
func (*earlySettingsTrace) Close() error                       { return nil }
func (t *earlySettingsTrace) RecordEvent(event qlogwriter.Event) {
	if frame, ok := event.(h3qlog.FrameCreated); ok {
		if _, ok := frame.Frame.Frame.(h3qlog.SettingsFrame); ok {
			t.mu.Lock()
			t.settingsCreated = true
			t.mu.Unlock()
		}
	}
	p, ok := event.(qlog.PacketSent)
	if !ok {
		return
	}
	if p.Header.PacketType == qlog.PacketType0RTT || p.Header.PacketType == qlog.PacketType1RTT {
		t.mu.Lock()
		for _, frame := range p.Frames {
			if stream, ok := frame.Frame.(*qlog.StreamFrame); ok && stream.StreamID == 0 {
				t.requestFrames = append(t.requestFrames, *stream)
			}
		}
		t.mu.Unlock()
	}
	if p.Header.PacketType == qlog.PacketTypeInitial {
		t.mu.Lock()
		hasCrypto := false
		for _, f := range p.Frames {
			if c, ok := f.Frame.(*qlog.CryptoFrame); ok {
				hasCrypto = true
				t.initialRanges = append(t.initialRanges, [2]int64{c.Offset, c.Offset + c.Length})
			}
		}
		if t.initialDatagrams == nil {
			t.initialDatagrams = make(map[qlog.DatagramPayloadChecksum]bool)
		}
		if hasCrypto && p.DatagramPayloadChecksum != 0 {
			t.initialDatagrams[p.DatagramPayloadChecksum] = true
		}
		t.mu.Unlock()
		return
	}
	if p.Header.PacketType != qlog.PacketType0RTT {
		return
	}
	packet := earlySettingsPacket{}
	request := false
	for _, frame := range p.Frames {
		if stream, ok := frame.Frame.(*qlog.StreamFrame); ok {
			packet.streams = append(packet.streams, *stream)
			request = request || stream.StreamID == 0
		}
	}
	t.mu.Lock()
	if len(t.packets) == 0 {
		ranges := append([][2]int64(nil), t.initialRanges...)
		slices.SortFunc(ranges, func(a, b [2]int64) int {
			if a[0] < b[0] {
				return -1
			}
			if a[0] > b[0] {
				return 1
			}
			return 0
		})
		var end int64
		t.firstEarlyComplete = len(ranges) > 0
		for _, r := range ranges {
			if r[0] > end {
				t.firstEarlyComplete = false
				break
			}
			end = max(end, r[1])
		}
		t.firstEarlyCoalesced = t.initialDatagrams[p.DatagramPayloadChecksum]
	}
	t.packets = append(t.packets, packet)
	t.mu.Unlock()
	if request {
		t.once.Do(func() { close(t.requestSent) })
	}
}

// A TLS server with a trusted test certificate holds its resumed ServerHello
// until a real encrypted early request is emitted. No scheduler sleep creates
// the 0-RTT opportunity. The server independently observes that request as early.
func TestHTTP3EarlySettingsFlushBeforeRequest(t *testing.T) {
	for _, profile := range []string{"custom", "chrome", "firefox"} {
		for _, large := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/large-control=%v", profile, large), func(t *testing.T) {
				requestSent := make(chan struct{})
				var reject atomic.Bool
				origin, observations := earlyDataServer(t, &reject, false, requestSent)
				cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				cert.Close()
				roots := x509.NewCertPool()
				roots.AddCert(cert.Certificate())
				cache := &h3SessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), stored: make(chan struct{}, 4)}
				b := surf.NewClient().Builder().Proxy("").Timeout(5 * time.Second)
				if profile == "chrome" {
					b.Impersonate().Chrome()
				} else if profile == "firefox" {
					b.Impersonate().Firefox()
					// A native-valid fixed DCID leaves a reproducible small tail after
					// the final Initial; larger IDs can legitimately leave no space.
					b.QUICSettings().InitialDestinationConnectionIDLengthFactory(func() (int, error) { return 8, nil }).Set()
				} else {
					b.HTTP3Settings().CoalesceInitialSettings(true).Set()
					// Give this custom peer enough immediate send credit to observe
					// both flushes. Pacing-limited readiness is tested independently.
					b.QUICSettings().Pacing(surf.PacingScheduled).PacingBurstPackets(10).
						FlushEarlyData(true).Set()
				}
				if large {
					b.HTTP3Settings().ControlGreaseFramesFactory(func() ([]http3.GreaseFrame, error) {
						return []http3.GreaseFrame{{Type: 33, Payload: make([]byte, 4096)}}, nil
					}).Set()
				}
				var mu sync.Mutex
				var traces []*earlySettingsTrace
				var setup atomic.Int32
				b.QUICSettings().OnEarlyDataReady(func(conn *quic.Conn) {
					setup.Add(1)
					select {
					case <-conn.HandshakeComplete():
						t.Error("setup ran after server confirmation")
					default:
					}
					mu.Lock()
					trace := traces[len(traces)-1]
					mu.Unlock()
					trace.mu.Lock()
					created := trace.settingsCreated
					trace.mu.Unlock()
					if !created {
						t.Error("application observer ran before HTTP/3 settings preparation")
					}
				}).Set()
				b.QUICSettings().Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
					trace := &earlySettingsTrace{requestSent: requestSent}
					mu.Lock()
					traces = append(traces, trace)
					mu.Unlock()
					return trace
				}).Set()
				c := b.ForceHTTP3().HTTP3Settings().EarlyData(true).Set().TLSConfig(&tls.Config{RootCAs: roots, ClientSessionCache: cache}).Build().Unwrap()
				defer c.Close()
				// Both settings and observers belong to the built transport snapshot.
				b.HTTP3Settings().FlushEarlySettings(false)
				b.QUICSettings().OnEarlyDataReady(func(*quic.Conn) { t.Error("late builder observer used by an existing client") })
				first := c.Get(g.String(origin)).Do().Unwrap()
				first.Body.String().Unwrap()
				require.False(t, (<-observations).early)
				select {
				case <-cache.stored:
				case <-time.After(5 * time.Second):
					t.Fatal("no session ticket")
				}
				require.Zero(t, setup.Load(), "a cold connection has no restored early keys")
				c.CloseIdleConnections()
				response := c.Get(g.String(origin)).Do().Unwrap()
				response.Body.String().Unwrap()
				state := response.GetResponse().TLS
				require.True(t, state.DidResume)
				require.NotEmpty(t, state.VerifiedChains)
				observed := <-observations
				require.True(t, observed.early)
				require.True(t, observed.resumed)
				require.EqualValues(t, 1, setup.Load())
				mu.Lock()
				snapshot := append([]*earlySettingsTrace(nil), traces...)
				mu.Unlock()
				require.Len(t, snapshot, 2)
				trace := snapshot[1]
				trace.mu.Lock()
				packets := append([]earlySettingsPacket(nil), trace.packets...)
				requestFrames := append([]qlog.StreamFrame(nil), trace.requestFrames...)
				complete, coalesced := trace.firstEarlyComplete, trace.firstEarlyCoalesced
				trace.mu.Unlock()
				require.NotEmpty(t, packets)
				require.True(t, complete, "early output overtook a hole in Initial CRYPTO")
				if profile != "custom" {
					require.Equal(t, profile == "firefox", coalesced, "wrong first-early datagram boundary")
				}
				var controlBytes int64
				firstRequest := -1
				for i, packet := range packets {
					for _, stream := range packet.streams {
						if stream.StreamID == 2 {
							controlBytes += stream.Length
						}
						if stream.StreamID == 0 && firstRequest == -1 {
							firstRequest = i
						}
					}
				}
				if profile == "chrome" || profile == "firefox" {
					assertFinishedHeadersFIN(t, requestFrames)
				}
				if profile == "firefox" {
					// Critical streams retain creation order in their normal class.
					// The finished request can precede them in its higher class.
					// Once that request unlocks the server handshake, remaining
					// critical prefixes can legitimately continue in 1-RTT.
					var firstStreams []quic.StreamID
					seen := make(map[quic.StreamID]bool)
					for _, packet := range packets {
						for _, stream := range packet.streams {
							if stream.StreamID == 0 || stream.Length == 0 || seen[stream.StreamID] {
								continue
							}
							seen[stream.StreamID] = true
							firstStreams = append(firstStreams, stream.StreamID)
						}
					}
					wantStreams := []quic.StreamID{2, 6, 10}
					require.NotEmpty(t, firstStreams)
					require.LessOrEqual(t, len(firstStreams), len(wantStreams))
					require.Equal(t, wantStreams[:len(firstStreams)], firstStreams)
					assertEarlyFinishedStreamOrder(t, packets, 0)
				} else {
					require.Greater(t, firstRequest, 0, "initial settings shared the first early packet with the request")
				}
				if large && profile != "firefox" {
					var beforeRequest int64
					for _, packet := range packets[:firstRequest] {
						for _, stream := range packet.streams {
							if stream.StreamID == 2 {
								beforeRequest += stream.Length
							}
						}
					}
					require.GreaterOrEqual(t, beforeRequest, int64(4096), "sendable initial control data was not flushed")
				}
				require.Positive(t, controlBytes)
			})
		}
	}
}
