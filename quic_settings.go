package surf

import (
	"context"
	"slices"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlogwriter"
)

// QUICSettings configures the HTTP/3 transport through Surf's fluent API.
// Each setter changes only its own option, retaining the selected browser profile.
// Set returns the main Builder; ForceHTTP3 selects use of this transport.
type QUICSettings struct {
	http3 *HTTP3Settings
}

// Set applies the accumulated QUIC settings and returns the main Builder.
func (q *QUICSettings) Set() *Builder { return q.http3.Set() }

func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		Versions:             []quic.Version{quic.Version1},
		EnableDatagrams:      true,
		HandshakeIdleTimeout: _quicHandshakeTimeout,
		MaxIdleTimeout:       _quicMaxIdleTimeout,
		KeepAlivePeriod:      _quicKeepAlivePeriod,
	}
}

func (q *QUICSettings) config() *quic.Config {
	if q.http3.quicConfig == nil {
		q.http3.quicConfig = defaultQUICConfig()
	}
	return q.http3.quicConfig
}

// Versions sets the allowed QUIC versions. The input slice is copied.
// An empty list selects the versions supported by quic-go.
func (q *QUICSettings) Versions(versions ...quic.Version) *QUICSettings {
	q.config().Versions = slices.Clone(versions)
	return q
}

// HandshakeIdleTimeout sets the idle timeout during connection establishment.
// Zero selects quic-go's default.
func (q *QUICSettings) HandshakeIdleTimeout(timeout time.Duration) *QUICSettings {
	q.config().HandshakeIdleTimeout = timeout
	return q
}

// MaxIdleTimeout sets the maximum idle time after the handshake.
// Zero selects quic-go's default.
func (q *QUICSettings) MaxIdleTimeout(timeout time.Duration) *QUICSettings {
	q.config().MaxIdleTimeout = timeout
	return q
}

// KeepAlivePeriod sets the interval between keep-alive packets. Zero disables them.
func (q *QUICSettings) KeepAlivePeriod(period time.Duration) *QUICSettings {
	q.config().KeepAlivePeriod = period
	return q
}

// InitialStreamReceiveWindow sets the common initial stream receive window.
// It replaces any per-direction StreamReceiveWindows override.
func (q *QUICSettings) InitialStreamReceiveWindow(size uint64) *QUICSettings {
	q.config().InitialStreamReceiveWindow = size
	q.handshake().StreamReceiveWindows = nil
	return q
}

// MaxStreamReceiveWindow sets the receive window limit for each stream.
func (q *QUICSettings) MaxStreamReceiveWindow(size uint64) *QUICSettings {
	q.config().MaxStreamReceiveWindow = size
	return q
}

// InitialConnectionReceiveWindow sets the initial connection receive window.
func (q *QUICSettings) InitialConnectionReceiveWindow(size uint64) *QUICSettings {
	q.config().InitialConnectionReceiveWindow = size
	return q
}

// MaxConnectionReceiveWindow sets the connection receive window limit.
func (q *QUICSettings) MaxConnectionReceiveWindow(size uint64) *QUICSettings {
	q.config().MaxConnectionReceiveWindow = size
	return q
}

// AllowConnectionWindowIncrease decides whether automatic receive window growth
// is permitted. The callback must not call connection or stream methods.
func (q *QUICSettings) AllowConnectionWindowIncrease(allow func(*quic.Conn, uint64) bool) *QUICSettings {
	q.config().AllowConnectionWindowIncrease = allow
	return q
}

// MaxIncomingStreams limits concurrent peer-initiated bidirectional streams.
// Zero selects quic-go's default; a negative value disallows them.
func (q *QUICSettings) MaxIncomingStreams(limit int64) *QUICSettings {
	q.config().MaxIncomingStreams = limit
	return q
}

// MaxIncomingUniStreams limits concurrent peer-initiated unidirectional streams.
// Zero selects quic-go's default; a negative value disallows them.
func (q *QUICSettings) MaxIncomingUniStreams(limit int64) *QUICSettings {
	q.config().MaxIncomingUniStreams = limit
	return q
}

// RequireStreamCreditRelease keeps completed peer streams counted until their
// credit is explicitly released. This is for applications managing incoming streams.
func (q *QUICSettings) RequireStreamCreditRelease(required bool) *QUICSettings {
	q.config().RequireStreamCreditRelease = required
	return q
}

// InitialPacketSize sets the initial packet size in bytes (at least 1200).
// Zero selects quic-go's default.
func (q *QUICSettings) InitialPacketSize(size uint16) *QUICSettings {
	q.config().InitialPacketSize = size
	return q
}

// DisablePathMTUDiscovery controls whether QUIC probes for a larger path MTU.
func (q *QUICSettings) DisablePathMTUDiscovery(disabled bool) *QUICSettings {
	q.config().DisablePathMTUDiscovery = disabled
	return q
}

// EnableDatagrams configures both QUIC and HTTP/3 datagram support.
func (q *QUICSettings) EnableDatagrams(enabled bool) *QUICSettings {
	q.config().EnableDatagrams = enabled
	q.http3.EnableDatagrams(enabled)

	if !enabled {
		q.handshake().MaxDatagramFrameSize = 0
	}

	return q
}

// EnableStreamResetPartialDelivery controls reliable stream resets.
func (q *QUICSettings) EnableStreamResetPartialDelivery(enabled bool) *QUICSettings {
	q.config().EnableStreamResetPartialDelivery = enabled
	return q
}

// TokenStore sets the shared store of address validation tokens. Nil disables it.
func (q *QUICSettings) TokenStore(store quic.TokenStore) *QUICSettings {
	q.config().TokenStore = store
	return q
}

// Tracer supplies a trace recorder for each new QUIC connection.
func (q *QUICSettings) Tracer(tracer func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace) *QUICSettings {
	q.config().Tracer = tracer
	return q
}

// ConnectionIDLength sets the local connection ID length, from 0 through 20.
// Zero uses a dedicated UDP socket for each connection.
func (q *QUICSettings) ConnectionIDLength(length int) *QUICSettings {
	q.http3.ConnectionIDLength(length)
	return q
}

// ConnectionIDGenerator sets a custom generator, taking precedence over length.
func (q *QUICSettings) ConnectionIDGenerator(generator quic.ConnectionIDGenerator) *QUICSettings {
	q.http3.ConnectionIDGenerator(generator)
	return q
}
