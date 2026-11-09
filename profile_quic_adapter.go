package surf

import (
	"context"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/tlsquic"
	"github.com/enetx/quic-go/transportparams"
	"github.com/enetx/surf/profiles"
	utls "github.com/refraction-networking/utls"
)

// quicadapter delegates profile chains to the public QUICSettings implementation.
type quicadapter struct{ s *QUICSettings }

func (a quicadapter) Versions(versions ...quic.Version) profiles.QUICConfig {
	a.s.Versions(versions...)
	return a
}

func (a quicadapter) HandshakeIdleTimeout(timeout time.Duration) profiles.QUICConfig {
	a.s.HandshakeIdleTimeout(timeout)
	return a
}

func (a quicadapter) MaxIdleTimeout(timeout time.Duration) profiles.QUICConfig {
	a.s.MaxIdleTimeout(timeout)
	return a
}

func (a quicadapter) KeepAlivePeriod(period time.Duration) profiles.QUICConfig {
	a.s.KeepAlivePeriod(period)
	return a
}

func (a quicadapter) InitialStreamReceiveWindow(size uint64) profiles.QUICConfig {
	a.s.InitialStreamReceiveWindow(size)
	return a
}

func (a quicadapter) MaxStreamReceiveWindow(size uint64) profiles.QUICConfig {
	a.s.MaxStreamReceiveWindow(size)
	return a
}

func (a quicadapter) InitialConnectionReceiveWindow(size uint64) profiles.QUICConfig {
	a.s.InitialConnectionReceiveWindow(size)
	return a
}

func (a quicadapter) MaxConnectionReceiveWindow(size uint64) profiles.QUICConfig {
	a.s.MaxConnectionReceiveWindow(size)
	return a
}

func (a quicadapter) AllowConnectionWindowIncrease(allow func(*quic.Conn, uint64) bool) profiles.QUICConfig {
	a.s.AllowConnectionWindowIncrease(allow)
	return a
}

func (a quicadapter) MaxIncomingStreams(limit int64) profiles.QUICConfig {
	a.s.MaxIncomingStreams(limit)
	return a
}

func (a quicadapter) MaxIncomingUniStreams(limit int64) profiles.QUICConfig {
	a.s.MaxIncomingUniStreams(limit)
	return a
}

func (a quicadapter) RequireStreamCreditRelease(required bool) profiles.QUICConfig {
	a.s.RequireStreamCreditRelease(required)
	return a
}

func (a quicadapter) InitialPacketSize(size uint16) profiles.QUICConfig {
	a.s.InitialPacketSize(size)
	return a
}

func (a quicadapter) DisablePathMTUDiscovery(disabled bool) profiles.QUICConfig {
	a.s.DisablePathMTUDiscovery(disabled)
	return a
}

func (a quicadapter) EnableDatagrams(enabled bool) profiles.QUICConfig {
	a.s.EnableDatagrams(enabled)
	return a
}

func (a quicadapter) EnableStreamResetPartialDelivery(enabled bool) profiles.QUICConfig {
	a.s.EnableStreamResetPartialDelivery(enabled)
	return a
}

func (a quicadapter) TokenStore(store quic.TokenStore) profiles.QUICConfig {
	a.s.TokenStore(store)
	return a
}

func (a quicadapter) Tracer(
	tracer func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace,
) profiles.QUICConfig {
	a.s.Tracer(tracer)
	return a
}

func (a quicadapter) ConnectionIDLength(length int) profiles.QUICConfig {
	a.s.ConnectionIDLength(length)
	return a
}

func (a quicadapter) ConnectionIDGenerator(generator quic.ConnectionIDGenerator) profiles.QUICConfig {
	a.s.ConnectionIDGenerator(generator)
	return a
}

func (a quicadapter) StreamReceiveWindows(bidiLocal, bidiRemote, uni uint64) profiles.QUICConfig {
	a.s.StreamReceiveWindows(bidiLocal, bidiRemote, uni)
	return a
}

func (a quicadapter) ClientHelloSpec(spec *utls.ClientHelloSpec) profiles.QUICConfig {
	a.s.ClientHelloSpec(spec)
	return a
}

func (a quicadapter) ClientHelloFactory(factory func() (utls.ClientHelloSpec, error)) profiles.QUICConfig {
	a.s.ClientHelloFactory(factory)
	return a
}

func (a quicadapter) TLSClientFactory(factory tlsquic.NewClient) profiles.QUICConfig {
	a.s.TLSClientFactory(factory)
	return a
}

func (a quicadapter) MaxUDPPayloadSize(size uint64) profiles.QUICConfig {
	a.s.MaxUDPPayloadSize(size)
	return a
}

func (a quicadapter) OmitMaxUDPPayloadSize(omit bool) profiles.QUICConfig {
	a.s.OmitMaxUDPPayloadSize(omit)
	return a
}

func (a quicadapter) MaxDatagramFrameSize(size uint64) profiles.QUICConfig {
	a.s.MaxDatagramFrameSize(size)
	return a
}

func (a quicadapter) MaxAckDelay(delay time.Duration) profiles.QUICConfig {
	a.s.MaxAckDelay(delay)
	return a
}

func (a quicadapter) ActiveConnectionIDLimit(limit uint64) profiles.QUICConfig {
	a.s.ActiveConnectionIDLimit(limit)
	return a
}

func (a quicadapter) OmitLegacyResetStreamAt(omit bool) profiles.QUICConfig {
	a.s.OmitLegacyResetStreamAt(omit)
	return a
}

func (a quicadapter) InitialDestinationConnectionIDLength(length int) profiles.QUICConfig {
	a.s.InitialDestinationConnectionIDLength(length)
	return a
}

func (a quicadapter) InitialPacketNumber(number uint64) profiles.QUICConfig {
	a.s.InitialPacketNumber(number)
	return a
}

func (a quicadapter) InitialPacketNumberFactory(factory func() (uint64, error)) profiles.QUICConfig {
	a.s.InitialPacketNumberFactory(factory)
	return a
}

func (a quicadapter) DisableClientHelloScrambling(disabled bool) profiles.QUICConfig {
	a.s.DisableClientHelloScrambling(disabled)
	return a
}

func (a quicadapter) TransportParameterOrder(ids ...uint64) profiles.QUICConfig {
	a.s.TransportParameterOrder(ids...)
	return a
}

func (a quicadapter) TransportParameter(id uint64, value []byte) profiles.QUICConfig {
	a.s.TransportParameter(id, value)
	return a
}

func (a quicadapter) DisableTransportParameterGrease(disabled bool) profiles.QUICConfig {
	a.s.DisableTransportParameterGrease(disabled)
	return a
}

func (a quicadapter) TransportParametersFactory(
	factory func(quic.Version) (*transportparams.Layout, error),
) profiles.QUICConfig {
	a.s.TransportParametersFactory(factory)
	return a
}
