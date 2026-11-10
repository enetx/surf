package surf_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type maxDataProbeTrace struct {
	sync.Mutex
	credits []int64
}

func (r *maxDataProbeTrace) AddProducer() qlogwriter.Recorder { return r }
func (*maxDataProbeTrace) Close() error                       { return nil }
func (r *maxDataProbeTrace) RecordEvent(event qlogwriter.Event) {
	packet, ok := event.(qlog.PacketReceived)
	if !ok {
		return
	}
	for _, frame := range packet.Frames {
		if f, ok := frame.Frame.(*qlog.MaxDataFrame); ok {
			r.Lock()
			r.credits = append(r.credits, int64(f.MaximumData))
			r.Unlock()
		}
	}
}

func TestQUICMaxDataAckProbeDoesNotGrantExtraCredit(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			certs := cert.TLS.Certificates
			cert.Close()
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			trace := new(maxDataProbeTrace)
			server := &http3.Server{TLSConfig: &tls.Config{Certificates: certs}, QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(make([]byte, 2<<20))
			})}
			go server.Serve(peer)
			t.Cleanup(func() { server.Close(); peer.Close() })
			b := surf.NewClient().Builder().Impersonate().Chrome().ForceHTTP3()
			if !enabled {
				b.QUICSettings().AckOnlyPingThreshold(-1).Set()
			}
			client := b.TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			response := client.Get(g.String("https://" + peer.LocalAddr().String())).Do().Unwrap()
			n, err := io.Copy(io.Discard, response.Body.Stream())
			response.Body.Close()
			require.NoError(t, err)
			require.EqualValues(t, 2<<20, n)
			trace.Lock()
			credits := append([]int64(nil), trace.credits...)
			trace.Unlock()
			if enabled {
				require.NotEmpty(t, credits)
			} else {
				require.Empty(t, credits)
			}
			for _, credit := range credits {
				require.EqualValues(t, 15<<20, credit, "probe must repeat the advertised credit")
			}
		})
	}
}
