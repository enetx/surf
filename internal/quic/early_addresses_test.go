package quictransport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

type addressEarlyTrace struct {
	sent chan struct{}
	once sync.Once
}

func (r *addressEarlyTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *addressEarlyTrace) Close() error                     { return nil }
func (r *addressEarlyTrace) RecordEvent(event qlogwriter.Event) {
	if packet, ok := event.(qlog.PacketSent); ok && packet.Header.PacketType == qlog.PacketType0RTT {
		for _, frame := range packet.Frames {
			if stream, ok := frame.Frame.(*qlog.StreamFrame); ok && stream.StreamID == 0 {
				r.once.Do(func() { close(r.sent) })
			}
		}
	}
}

type addressSessionCache struct {
	tls.ClientSessionCache
	stored chan struct{}
}

func (c *addressSessionCache) Put(key string, value *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, value)
	if value != nil {
		select {
		case c.stored <- struct{}{}:
		default:
		}
	}
}

func TestAddressRacingWithEarlyData(t *testing.T) {
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsConfig := cert.TLS.Clone()
	cert.Close()
	trace := &addressEarlyTrace{sent: make(chan struct{})}
	var handshakes, requests, attempts atomic.Int32
	tlsConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) == 1 {
			return nil, nil
		}
		select {
		case <-trace.sent:
			return nil, nil
		case <-info.Context().Done():
			return nil, info.Context().Err()
		}
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	server := &http3.Server{TLSConfig: tlsConfig, QUICConfig: &quic.Config{Allow0RTT: true}, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); io.WriteString(w, "ok") })}
	defer server.Close()
	dialer := &Dialer{Lazy: true, AddressFallbackDelay: 10 * time.Millisecond}
	defer dialer.Close()
	cache := &addressSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), stored: make(chan struct{}, 4)}
	_, port, err := net.SplitHostPort(udp.LocalAddr().String())
	require.NoError(t, err)
	alive, unreachable := udp.LocalAddr().String(), net.JoinHostPort("127.0.0.2", port)
	var warm atomic.Bool
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}, QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { attempts.Add(1); return trace }}, Dial: func(ctx context.Context, _ string, config *tls.Config, q *quic.Config) (*quic.Conn, error) {
		addresses := []string{unreachable, alive}
		if warm.Load() {
			addresses = []string{alive, unreachable}
		}
		return dialer.dialAddresses(ctx, addresses, config, q, true)
	}}
	defer tr.Close()
	defer trace.once.Do(func() { close(trace.sent) })
	go server.Serve(udp)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http3.MethodGet0RTT, "https://localhost:"+port, nil)
	require.NoError(t, err)
	response, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	response.Body.Close()
	require.EqualValues(t, 2, attempts.Load(), "cold resolution must advance past the unresponsive address")
	require.EqualValues(t, 1, requests.Load())
	select {
	case <-cache.stored:
	case <-ctx.Done():
		t.Fatal("no resumable session")
	}
	tr.CloseIdleConnections()
	warm.Store(true)
	response, err = tr.RoundTrip(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	response.Body.Close()
	select {
	case <-trace.sent:
	default:
		t.Fatal("address preparation suppressed the eligible early request")
	}
	require.EqualValues(t, 3, attempts.Load(), "early-ready winner cancels the remaining address timer")
	require.EqualValues(t, 2, requests.Load(), "only one address owns each request")
}
