package surf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"slices"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
)

// AltUsed sends the current request's destination authority in the Alt-Used
// header on HTTP/3 attempts. The Firefox desktop profile enables this to match
// its captured alternative-service requests. Explicit headers take precedence.
// Port 443 is omitted; non-default ports and IPv6 brackets are preserved.
func (h *HTTP3Settings) AltUsed(enabled bool) *HTTP3Settings {
	h.altUsed = enabled
	return h
}

// QUICConfig replaces Surf's QUIC defaults with a snapshot of config.
// Zero-valued fields use the official quic-go defaults. Nil restores Surf's
// defaults. Token stores, tracers and callbacks retain their shared identity.
// RequireStreamCreditRelease is an advanced option for applications that manage
// incoming stream credit; it does not add a transport parameter to the handshake.
// Use Builder.QUICSettings for fluent configuration of individual options.
func (h *HTTP3Settings) QUICConfig(config *quic.Config) *HTTP3Settings {
	h.quicConfig = cloneQUICConfig(config)
	return h
}

// ConnectionIDLength sets the length of locally generated connection IDs.
// Valid explicit lengths are 0 through 20. Zero uses a zero-length generator and
// a dedicated UDP socket per connection. Unset retains quic-go's 4-byte default.
// This does not control the independently generated initial destination ID.
func (h *HTTP3Settings) ConnectionIDLength(length int) *HTTP3Settings {
	h.connectionIDLength = new(length)
	return h
}

// AdditionalSettings merges ordered HTTP/3 SETTINGS. Existing keys keep their
// position; new keys append in input order. Advertising a setting does not add
// implementation support for extensions such as WebTransport. QPACK settings
// configure the receive-side decoder; outbound encoding remains static.
func (h *HTTP3Settings) AdditionalSettings(settings g.MapOrd[uint64, uint64]) *HTTP3Settings {
	for id, value := range settings.Iter() {
		h.settings.Insert(id, value)
	}

	return h
}

// EnableDatagrams configures both QUIC and HTTP/3 datagram support.
func (h *HTTP3Settings) EnableDatagrams(enabled bool) *HTTP3Settings {
	h.datagrams = new(enabled)

	value := uint64(0)
	if enabled {
		value = 1
	}

	h.settings.Insert(SETTINGS_H3_DATAGRAM, value)

	return h
}

// MaxResponseHeaderBytes sets the local response header limit. Zero restores
// Surf's default. Use MaxFieldSectionSize separately for the advertised setting.
func (h *HTTP3Settings) MaxResponseHeaderBytes(limit int) *HTTP3Settings {
	h.maxResponseHeaderBytes = limit
	return h
}

// ConnectionIDGenerator supplies the official quic-go connection ID generator.
// It takes precedence over ConnectionIDLength and may generate zero-length IDs.
func (h *HTTP3Settings) ConnectionIDGenerator(generator quic.ConnectionIDGenerator) *HTTP3Settings {
	h.connectionIDGenerator = generator
	return h
}

// StreamPriority sets local QUIC scheduling for request data. Urgency is clipped
// to 0 through 7 by quic-go. This does not send a PRIORITY_UPDATE frame or set
// the HTTP Priority header.
func (h *HTTP3Settings) StreamPriority(urgency int8, incremental bool) *HTTP3Settings {
	h.streamPriority = &http3.StreamPriority{Urgency: urgency, Incremental: incremental}
	return h
}

func cloneQUICConfig(config *quic.Config) *quic.Config {
	if config == nil {
		return nil
	}

	copy := config.Clone()
	copy.Versions = slices.Clone(config.Versions)

	return copy
}

func (ut *uquicTransport) newQUICTransport(conn net.PacketConn) *quic.Transport {
	return &quic.Transport{
		Conn: conn, ConnectionIDLength: ut.connectionIDLength, ReceivePacketSize: ut.receivePacketSize,
		ConnectionIDGenerator: ut.connectionIDGenerator,
	}
}

func (h *HTTP3Settings) validateQUICConfig() error {
	if err := h.qpackConfig.Validate(); err != nil {
		return err
	}
	length := 0

	if h.connectionIDLength != nil {
		length = *h.connectionIDLength
	}

	if h.connectionIDGenerator != nil {
		length = h.connectionIDGenerator.ConnectionIDLen()
	}

	if length < 0 || length > 20 {
		return fmt.Errorf("HTTP/3 connection ID length must be between 0 and 20: %d", length)
	}

	if h.maxResponseHeaderBytes < 0 {
		return fmt.Errorf("HTTP/3 response header limit must not be negative")
	}

	return nil
}

type zeroConnectionIDGenerator struct{}

func (zeroConnectionIDGenerator) ConnectionIDLen() int { return 0 }
func (zeroConnectionIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionIDFromBytes(nil), nil
}

// Zero-length CIDs cannot demultiplex connections on a shared socket. Proxy
// relays also own their sockets. Close each private transport with its connection.
func (ut *uquicTransport) dialOwnedPacketConn(
	ctx context.Context,
	packetConn net.PacketConn,
	addr net.Addr,
	tlsConfig *tls.Config,
	config *quic.Config,
	early bool,
) (*quic.Conn, error) {
	transport := ut.newQUICTransport(packetConn)
	dial := transport.Dial

	if early {
		dial = transport.DialEarly
	}

	conn, err := dial(ctx, addr, tlsConfig, config)
	if err != nil {
		transport.Close()
		packetConn.Close()
		return nil, err
	}

	go func() {
		<-conn.Context().Done()
		transport.Close()
		packetConn.Close()
	}()

	return conn, nil
}
