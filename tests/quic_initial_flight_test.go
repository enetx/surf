package surf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

type handshakeFlightTrace struct {
	sync.Mutex
	newIDs    []uint64
	handshake []bool // whether a sent Handshake packet contains CRYPTO
}

func (r *handshakeFlightTrace) AddProducer() qlogwriter.Recorder { return r }
func (*handshakeFlightTrace) Close() error                       { return nil }
func (r *handshakeFlightTrace) RecordEvent(event qlogwriter.Event) {
	p, ok := event.(qlog.PacketSent)
	if !ok {
		return
	}
	if p.Header.PacketType == qlog.PacketType1RTT {
		r.Lock()
		for _, f := range p.Frames {
			if id, ok := f.Frame.(*qlog.NewConnectionIDFrame); ok {
				r.newIDs = append(r.newIDs, id.SequenceNumber)
			}
		}
		r.Unlock()
		return
	}
	if p.Header.PacketType != qlog.PacketTypeHandshake {
		return
	}
	crypto := false
	for _, f := range p.Frames {
		if _, ok := f.Frame.(*qlog.CryptoFrame); ok {
			crypto = true
		}
	}
	r.Lock()
	r.handshake = append(r.handshake, crypto)
	r.Unlock()
}

func TestQUICInitialFlightOptionsAreIndependent(t *testing.T) {
	for _, mode := range []quic.InitialPaddingMode{quic.InitialPaddingPacket, quic.InitialPaddingDatagram} {
		for _, separate := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode=%d/separate=%v", mode, separate), func(t *testing.T) {
				peer := newH3Peer(t)
				trace := new(handshakeFlightTrace)
				client := surf.NewClient().Builder().Impersonate().Firefox().QUICSettings().
					InitialPaddingMode(mode).HandshakeAckBeforeData(separate).
					Tracer(func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }).Set().
					HTTP3Settings().CoalesceInitialSettings(true).Set().ForceHTTP3().
					TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
				defer client.Close()
				peer.request(t, client)
				trace.Lock()
				packets := append([]bool(nil), trace.handshake...)
				newIDs := append([]uint64(nil), trace.newIDs...)
				trace.Unlock()
				require.Equal(t, []uint64{1, 2, 3}, newIDs)
				require.NotEmpty(t, packets)
				require.Equal(t, !separate, packets[0], "first Handshake must follow the selected ACK/data policy")
				require.Contains(t, packets, true, "local Finished was never sent")
				// The independent Initial decoder must still reconstruct ClientHello when
				// there are zero bytes outside the encoded Initial length.
				hello, _ := h3CapturedHello(t, peer)
				require.Greater(t, len(hello), 1000)
			})
		}
	}
}

func TestQUICInitialFlightPreservesCertificateVerification(t *testing.T) {
	peer := newH3Peer(t)
	failure := errors.New("certificate explicitly rejected")
	var verified atomic.Int32
	client := surf.NewClient().Builder().Impersonate().Firefox().ForceHTTP3().
		TLSConfig(&tls.Config{InsecureSkipVerify: true, VerifyConnection: func(tls.ConnectionState) error { verified.Add(1); return failure }}).
		Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	response := client.Get(g.String(peer.url)).Do()
	require.True(t, response.IsErr())
	require.ErrorContains(t, response.Err(), failure.Error())
	require.EqualValues(t, 1, verified.Load())
	select {
	case <-peer.requests:
		t.Fatal("HTTP request reached peer after failed verification")
	default:
	}
}

func TestQUICDatagramPaddingWithProtectedClientHello(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprint(separate), func(t *testing.T) {
			peer := newH3Peer(t)
			client := surf.NewClient().Builder().Impersonate().Chrome().QUICSettings().
				InitialPaddingMode(surf.InitialPaddingDatagram).HandshakeAckBeforeData(separate).Set().
				ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			peer.request(t, client)
			hello, _ := h3CapturedHello(t, peer)
			require.Greater(t, len(hello), 1000, "fragmented ClientHello was not reassembled")
		})
	}
}
