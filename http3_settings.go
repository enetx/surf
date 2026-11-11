package surf

import (
	"context"
	"math"
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/internal/clientdialer"
	h3transport "github.com/enetx/surf/internal/http3"
	quictransport "github.com/enetx/surf/internal/quic"
	"github.com/enetx/surf/internal/specclone"
	"github.com/enetx/surf/profiles"
	utls "github.com/enetx/utls"
)

// HTTP/3 SETTINGS frame parameter identifiers as defined in RFC 9114.
const (
	SETTINGS_QPACK_MAX_TABLE_CAPACITY = h3transport.SETTINGS_QPACK_MAX_TABLE_CAPACITY
	SETTINGS_MAX_FIELD_SECTION_SIZE   = h3transport.SETTINGS_MAX_FIELD_SECTION_SIZE
	SETTINGS_QPACK_BLOCKED_STREAMS    = h3transport.SETTINGS_QPACK_BLOCKED_STREAMS
	SETTINGS_ENABLE_CONNECT_PROTOCOL  = h3transport.SETTINGS_ENABLE_CONNECT_PROTOCOL
	SETTINGS_H3_DATAGRAM              = h3transport.SETTINGS_H3_DATAGRAM
	H3_DATAGRAM                       = h3transport.H3_DATAGRAM
	SETTINGS_ENABLE_WEBTRANSPORT      = h3transport.SETTINGS_ENABLE_WEBTRANSPORT
)

// HTTP3Settings configures HTTP/3 SETTINGS, response limits and request options.
// Use Builder.QUICSettings for the underlying QUIC transport and handshake.
type HTTP3Settings struct {
	options    h3transport.Options
	builder    *Builder
	registered bool
}

// HTTP3GreaseFrame describes one RFC 9114 reserved frame and its payload.
type HTTP3GreaseFrame = http3.GreaseFrame

// HTTP3RequestBodyReadInfo contains validated wire fields and the effective buffer size.
type HTTP3RequestBodyReadInfo = http3.RequestBodyReadInfo

type (
	ConnectionRacingInfo   = profiles.ConnectionRacingInfo
	ConnectionRacingPolicy = profiles.ConnectionRacingPolicy
)

// HTTPSRecord describes an RFC 9460 HTTPS service binding. Lookup callbacks
// must return resolved ServiceMode bindings with owned slices and honor
// cancellation. The built-in resolver follows CNAME/AliasMode chains.
type HTTPSRecord struct {
	Priority           uint16
	Target             string
	ALPN               []string
	Port               uint16
	IPv4Hint, IPv6Hint []netip.Addr
	TTL                time.Duration
	ECH                []byte
	Mandatory          []uint16
	NoDefaultALPN      bool
}

type (
	HTTPSRecordsLookup        func(context.Context, string) ([]HTTPSRecord, error)
	AlternativeServiceBackoff = func(consecutiveFailures uint32) time.Duration
)

// HTTP3PriorityUpdater queues RFC 9218 priority changes for one open request.
// Update is concurrency safe; it does not change local QUIC upload scheduling.
type HTTP3PriorityUpdater = http3.PriorityUpdater

// QpackMaxTableCapacity sets the advertised and enforced receive-side QPACK
// dynamic table capacity. Zero selects the static-only decoder.
func (h *HTTP3Settings) QpackMaxTableCapacity(num uint64) *HTTP3Settings {
	h.options.Settings.Insert(SETTINGS_QPACK_MAX_TABLE_CAPACITY, num)
	return h
}

// MaxFieldSectionSize sets the maximum size of a field section the peer is willing to accept.
func (h *HTTP3Settings) MaxFieldSectionSize(num uint64) *HTTP3Settings {
	h.options.Settings.Insert(SETTINGS_MAX_FIELD_SECTION_SIZE, num)
	return h
}

// QpackBlockedStreams sets the maximum number of streams that can be blocked on QPACK.
func (h *HTTP3Settings) QpackBlockedStreams(num uint64) *HTTP3Settings {
	h.options.Settings.Insert(SETTINGS_QPACK_BLOCKED_STREAMS, num)
	return h
}

// EnableConnectProtocol enables the extended CONNECT protocol (RFC 9220).
func (h *HTTP3Settings) EnableConnectProtocol(num uint64) *HTTP3Settings {
	h.options.Settings.Insert(SETTINGS_ENABLE_CONNECT_PROTOCOL, num)
	return h
}

// SettingsH3Datagram sets the H3_DATAGRAM setting value.
func (h *HTTP3Settings) SettingsH3Datagram(num uint64) *HTTP3Settings {
	h.options.Settings.Insert(SETTINGS_H3_DATAGRAM, num)
	return h
}

// H3Datagram sets a custom H3_DATAGRAM value for datagram support.
func (h *HTTP3Settings) H3Datagram(num uint64) *HTTP3Settings {
	h.options.Settings.Insert(H3_DATAGRAM, num)
	return h
}

// EnableWebtransport advertises a WebTransport setting. It does not implement
// a WebTransport application protocol.
func (h *HTTP3Settings) EnableWebtransport(num uint64) *HTTP3Settings {
	h.options.Settings.Insert(SETTINGS_ENABLE_WEBTRANSPORT, num)
	return h
}

// Grease generates a fresh reserved SETTINGS identifier/value per connection.
// Call GreaseFactory(nil) to disable generated SETTINGS GREASE.
func (h *HTTP3Settings) Grease() *HTTP3Settings {
	return h.GreaseFactory(func() (uint64, uint64, error) {
		return 0x1f*uint64(rand.Uint32()) + 0x21, uint64(rand.Uint32()), nil
	})
}

// GreaseFactory generates one reserved SETTINGS pair for each new HTTP/3
// connection. It must be concurrency safe, return promptly and not reenter the
// transport. Nil disables it. Errors are returned before control-stream writes.
func (h *HTTP3Settings) GreaseFactory(factory func() (uint64, uint64, error)) *HTTP3Settings {
	h.wire().SettingsGrease = factory
	return h
}

// Set applies the configured HTTP/3 settings to the client's transport.
func (h *HTTP3Settings) Set() *Builder {
	if h.registered {
		return h.builder
	}

	h.registered = true

	return h.builder.addCliMW(func(c *Client) error {
		forcedTCP := h.builder.forceHTTP1 || h.builder.forceHTTP2
		if !h.options.Discovery && (forcedTCP || !h.builder.forceHTTP3) {
			return nil
		}

		// An application-owned transport or TLS dialer keeps ownership of its
		// connection policy. Automatic discovery also needs reusable TCP pools.
		if h.options.Discovery && (forcedTCP || !h.builder.forceHTTP3) {
			base := c.GetTransport()
			if _, ok := base.(h3transport.Preconnector); !ok {
				return nil
			}

			if tcp, ok := base.(*http.Transport); ok &&
				(tcp.DialTLSContext != nil || !forcedTCP && (tcp.DisableKeepAlives || tcp.MaxIdleConnsPerHost < 0)) {
				return nil
			}
		}

		transport, err := h.newTransport(c)
		if err != nil {
			return err
		}

		c.GetClient().Transport = transport
		c.transport = transport

		return nil
	}, math.MaxInt-1)
}

// EarlyData opts bodyless GET and HEAD requests into TLS 0-RTT on resumed
// HTTP/3 connections. Disabled by default. Enable only when replay of these
// requests is acceptable; POST and requests with bodies always wait for 1-RTT.
// A TLS ClientSessionCache is needed to resume a connection. Standard TLS and
// custom browser ClientHello templates support this, including accepted ECH.
func (h *HTTP3Settings) EarlyData(enabled bool) *HTTP3Settings {
	h.options.EarlyData = enabled
	return h
}

// AltUsed sends the current request's destination authority in the Alt-Used
// header on HTTP/3 attempts. The Firefox desktop profile enables this to match
// its captured alternative-service requests. Explicit headers take precedence.
// Port 443 is omitted; non-default ports and IPv6 brackets are preserved.
func (h *HTTP3Settings) AltUsed(enabled bool) *HTTP3Settings {
	h.options.AltUsed = enabled
	return h
}

// QUICConfig replaces Surf's QUIC defaults with a snapshot of config.
// Zero-valued fields use the official quic-go defaults. Nil restores Surf's
// defaults. Token stores, tracers and callbacks retain their shared identity.
// RequireStreamCreditRelease is an advanced option for applications that manage
// incoming stream credit; it does not add a transport parameter to the handshake.
// Use Builder.QUICSettings for fluent configuration of individual options.
func (h *HTTP3Settings) QUICConfig(config *quic.Config) *HTTP3Settings {
	h.options.QUICConfig = quictransport.CloneConfig(config)
	return h
}

// ConnectionIDLength sets the length of locally generated connection IDs.
// Valid explicit lengths are 0 through 20. Zero uses a zero-length generator and
// a dedicated UDP socket per connection. Unset retains quic-go's 4-byte default.
// This does not control the independently generated initial destination ID.
func (h *HTTP3Settings) ConnectionIDLength(length int) *HTTP3Settings {
	h.options.ConnectionIDLength = new(length)
	return h
}

// AdditionalSettings merges ordered HTTP/3 SETTINGS. Existing keys keep their
// position; new keys append in input order. Advertising a setting does not add
// implementation support for extensions such as WebTransport. QPACK settings
// configure the receive-side decoder; request encoding is configured separately.
func (h *HTTP3Settings) AdditionalSettings(settings g.MapOrd[uint64, uint64]) *HTTP3Settings {
	for id, value := range settings.Iter() {
		h.options.Settings.Insert(id, value)
	}

	return h
}

// EnableDatagrams configures both QUIC and HTTP/3 datagram support.
func (h *HTTP3Settings) EnableDatagrams(enabled bool) *HTTP3Settings {
	h.options.Datagrams = new(enabled)

	value := uint64(0)
	if enabled {
		value = 1
	}

	h.options.Settings.Insert(SETTINGS_H3_DATAGRAM, value)

	return h
}

// MaxResponseHeaderBytes sets the local response header limit. Zero restores
// Surf's default. Use MaxFieldSectionSize separately for the advertised setting.
func (h *HTTP3Settings) MaxResponseHeaderBytes(limit int) *HTTP3Settings {
	h.options.MaxResponseHeaderBytes = limit
	return h
}

// ConnectionIDGenerator supplies the official quic-go connection ID generator.
// It takes precedence over ConnectionIDLength and may generate zero-length IDs.
func (h *HTTP3Settings) ConnectionIDGenerator(generator quic.ConnectionIDGenerator) *HTTP3Settings {
	h.options.ConnectionIDGenerator = generator
	return h
}

// StreamPriority sets local QUIC scheduling for request data. Urgency is clipped
// to 0 through 7 by quic-go. This does not send a PRIORITY_UPDATE frame or set
// the HTTP Priority header.
func (h *HTTP3Settings) StreamPriority(urgency int8, incremental bool) *HTTP3Settings {
	h.options.StreamPriority = &http3.StreamPriority{Urgency: urgency, Incremental: incremental}
	return h
}

func (h *HTTP3Settings) wire() *http3.WireConfig {
	if h.options.WireConfig == nil {
		h.options.WireConfig = &http3.WireConfig{}
	}

	return h.options.WireConfig
}

// ControlGreaseFrames adds reserved frames after SETTINGS on every connection.
// Types must be 0x1f*N+0x21. Frames and payloads are copied.
func (h *HTTP3Settings) ControlGreaseFrames(frames ...HTTP3GreaseFrame) *HTTP3Settings {
	copy := h3transport.CloneGreaseFrames(frames)
	return h.ControlGreaseFramesFactory(func() ([]HTTP3GreaseFrame, error) { return copy, nil })
}

// ControlGreaseFramesFactory generates fresh frames once per connection.
// The callback must be safe for concurrent connections.
func (h *HTTP3Settings) ControlGreaseFramesFactory(factory func() ([]HTTP3GreaseFrame, error)) *HTTP3Settings {
	h.wire().ControlGreaseFrames = factory
	return h
}

// RequestGreaseFrames adds reserved frames before each request's HEADERS.
// Types must be 0x1f*N+0x21. Frames and payloads are copied.
func (h *HTTP3Settings) RequestGreaseFrames(frames ...HTTP3GreaseFrame) *HTTP3Settings {
	copy := h3transport.CloneGreaseFrames(frames)
	return h.RequestGreaseFramesFactory(func(*http.Request) ([]HTTP3GreaseFrame, error) { return copy, nil })
}

// RequestGreaseFramesFactory generates frames for each request. The callback
// must be safe for concurrent connections and must not mutate the request.
func (h *HTTP3Settings) RequestGreaseFramesFactory(
	factory func(*http.Request) ([]HTTP3GreaseFrame, error),
) *HTTP3Settings {
	h.wire().RequestGreaseFrames = factory
	return h
}

// PriorityUpdates sends RFC 9218 control frames for explicit, nondefault
// request Priority headers. Independent of GREASE and local StreamPriority.
func (h *HTTP3Settings) PriorityUpdates(enabled bool) *HTTP3Settings {
	h.wire().SendPriorityUpdates = enabled
	return h
}

// CoalesceInitialSettings queues SETTINGS with the first post-handshake flight
// when peer flow-control credit permits. Backpressure uses an asynchronous
// write on the same control stream. Control frame factories must not block.
func (h *HTTP3Settings) CoalesceInitialSettings(enabled bool) *HTTP3Settings {
	h.wire().CoalesceInitialSettings = enabled
	return h
}

// CoalesceRequestHeaders stages initial priority, HEADERS and a bodyless
// request's FIN together. Blocked streams retain asynchronous control writes.
func (h *HTTP3Settings) CoalesceRequestHeaders(enabled bool) *HTTP3Settings {
	h.wire().CoalesceRequestHeaders = enabled
	return h
}

// RequestBodyBufferSize sets reads from HTTP/3 request bodies (0 uses 8 KiB).
// It clears previously configured size and first-read policies. Sizes must be in [0, 16 MiB].
func (h *HTTP3Settings) RequestBodyBufferSize(size int) *HTTP3Settings {
	h.wire().RequestBodyBufferSize = size
	h.wire().RequestBodyBufferSizePolicy = nil
	h.wire().RequestBodyFirstReadSizePolicy = nil

	return h
}

// RequestBodyBufferSizePolicy chooses a buffer using ContentLength (-1 when
// unknown). It must be concurrency safe; zero uses 8 KiB. Nil restores the fixed size.
func (h *HTTP3Settings) RequestBodyBufferSizePolicy(policy func(int64) int) *HTTP3Settings {
	h.wire().RequestBodyBufferSizePolicy = policy
	return h
}

// MaxDataFrameSize caps request DATA payloads. Zero preserves one frame per
// body read or Write. This does not set QUIC packet boundaries.
func (h *HTTP3Settings) MaxDataFrameSize(size int) *HTTP3Settings {
	h.wire().MaxDataFrameSize = size
	return h
}

// RequestBodyFirstReadSizePolicy caps the first nonempty HTTP/3 body read.
// Zero restores the normal buffer size; a positive result must not exceed it.
// The callback receives actual outgoing fields, including implicit headers, and
// runs before request bytes or QPACK state changes. It must be concurrency safe.
// Nil clears this policy. It does not change QUIC packet boundaries.
func (h *HTTP3Settings) RequestBodyFirstReadSizePolicy(policy func(HTTP3RequestBodyReadInfo) int) *HTTP3Settings {
	h.wire().RequestBodyFirstReadSizePolicy = policy
	return h
}

// ClientHandshake sets optional QUIC handshake controls. The supplied values are
// snapshotted; nil removes this override and retains any QUICConfig controls.
// Use Builder.QUICSettings for fluent configuration of individual controls.
func (h *HTTP3Settings) ClientHandshake(config *quic.ClientHandshake) *HTTP3Settings {
	h.options.ClientHandshake = config.Clone()
	return h
}

// ClientHelloSpec sets an explicit QUIC ClientHello template. It must contain
// QUICTransportParametersExtension and ALPNExtension; TCP templates are rejected.
// QUIC supplies real transport parameters and the HTTP/3 ALPN for each dial.
// Browser TCP JA settings remain independent. Nil restores standard crypto/tls.
func (h *HTTP3Settings) ClientHelloSpec(spec *utls.ClientHelloSpec) *HTTP3Settings {
	if spec == nil {
		h.options.ClientHelloFactory = nil
		return h
	}

	snapshot := specclone.Clone(spec)
	h.options.ClientHelloFactory = func() (utls.ClientHelloSpec, error) { return *specclone.Clone(snapshot), nil }

	return h
}

// ClientHelloFactory supplies a fresh QUIC template per connection attempt,
// including retries after version negotiation. The factory may run concurrently.
// Returned templates must not share mutable extensions with other attempts.
func (h *HTTP3Settings) ClientHelloFactory(factory func() (utls.ClientHelloSpec, error)) *HTTP3Settings {
	h.options.ClientHelloFactory = factory
	return h
}

// ConnectionRacing enables connection-only competition between HTTP/3 and a TCP
// backup. No request headers or body are sent until a connection wins. Disabled
// by default, independently of the selected profile's delay policy.
func (h *HTTP3Settings) ConnectionRacing(enabled bool) *HTTP3Settings {
	h.options.ConnectionRacing = enabled
	return h
}

// TCPFallbackDelay replaces the profile's policy with a fixed nonnegative delay.
// Zero starts both handshakes immediately. Enable with ConnectionRacing(true).
func (h *HTTP3Settings) TCPFallbackDelay(delay time.Duration) *HTTP3Settings {
	h.options.TCPFallbackDelay = new(delay)
	return h
}

// ConnectionRacingPolicy selects a delay from per-origin observations. Nil uses
// Surf's 100ms default. Enable separately with ConnectionRacing(true). This setter
// replaces any fixed delay previously selected with TCPFallbackDelay.
func (h *HTTP3Settings) ConnectionRacingPolicy(policy ConnectionRacingPolicy) *HTTP3Settings {
	h.options.ConnectionRacingPolicy = policy
	h.options.TCPFallbackDelay = nil
	return h
}

// Discovery learns HTTP/3 alternatives from authenticated Alt-Svc responses
// and HTTPS DNS records. Without an advertisement requests use TCP. ForceHTTP3
// retains its direct-attempt behavior. Cache and failures belong to this client.
func (h *HTTP3Settings) Discovery(enabled bool) *HTTP3Settings {
	h.options.Discovery = enabled
	return h
}

// HTTPSRecordsWait chooses the extra wait for an optional built-in HTTPS DNS
// query after address queries finish. Zero means no supplemental deadline.
// Explicit HTTPSRecordsLookup callbacks retain their own deadlines.
func (h *HTTP3Settings) HTTPSRecordsWait(policy func(time.Duration) time.Duration) *HTTP3Settings {
	h.options.HTTPSRecordsWait = policy
	return h
}

// HTTPSRecordsLookup supplies HTTPS records from an application resolver. Nil
// uses the client's configured DNS transport and system resolver addresses.
// No public DNS provider is substituted. Proxies bypass local HTTPS discovery.
func (h *HTTP3Settings) HTTPSRecordsLookup(lookup HTTPSRecordsLookup) *HTTP3Settings {
	if lookup == nil {
		h.options.HTTPSRecordsLookup = nil
	} else {
		h.options.HTTPSRecordsLookup = func(ctx context.Context, name string) ([]h3transport.HTTPSRecord, error) {
			records, err := lookup(ctx, name)
			if records == nil {
				return nil, err
			}
			converted := make([]h3transport.HTTPSRecord, len(records))
			for i, record := range records {
				converted[i] = h3transport.HTTPSRecord(record)
			}
			return converted, err
		}
	}
	return h
}

// AlternativeServiceBackoff selects the retry delay after a failed alternative
// handshake. Cancellation and a TCP race win do not count as service failure.
// The callback must be prompt, concurrency safe, and must not reenter this client.
func (h *HTTP3Settings) AlternativeServiceBackoff(policy AlternativeServiceBackoff) *HTTP3Settings {
	h.options.AlternativeServiceBackoff = policy
	return h
}

// ExpireFailedAlternatives discards a failed advertisement when its retry
// interval expires; a new advertisement or DNS answer is then required.
func (h *HTTP3Settings) ExpireFailedAlternatives(enabled bool) *HTTP3Settings {
	h.options.ExpireFailedAlternatives = enabled
	return h
}

// HTTP3PriorityUpdates calls handler after HTTP/3 request HEADERS are sent on
// each attempt. Return promptly; retain the updater to change priority while
// the response is open. HTTP/1 and HTTP/2 do not invoke the handler.
func (req *Request) HTTP3PriorityUpdates(handler func(*HTTP3PriorityUpdater)) *Request {
	req.http3PriorityHandler = handler
	req.http3PrioritySet = true

	return req
}

// CompactPriorityUpdates omits spaces after commas in PRIORITY_UPDATE fields.
// It applies to initial frames and later HTTP3PriorityUpdater.Update calls.
func (h *HTTP3Settings) CompactPriorityUpdates(enabled bool) *HTTP3Settings {
	h.wire().CompactPriorityUpdates = enabled
	return h
}

func (req *Request) prepareHTTP3Priority() {
	if req.http3PrioritySet {
		req.request = req.request.WithContext(
			http3.WithPriorityUpdateHandler(req.request.Context(), req.http3PriorityHandler),
		)
	}
}

func (h *HTTP3Settings) newTransport(c *Client) (*h3transport.Transport, error) {
	options := h.options
	builder := h.builder

	options.ForceHTTP3 = builder.forceHTTP3

	if builder.forceHTTP1 {
		options.TCPVersion = 1
	} else if builder.forceHTTP2 {
		options.TCPVersion = 2
	}

	options.Proxy = builder.proxy.Std()
	options.DisableCompression = builder.disableCompression
	options.ProtocolHeaders = builder.protocolHeaders
	options.Fallback = c.GetTransport()
	options.TLSConfig = c.GetTLSConfig()
	options.Dialer = c.GetDialer()

	if base, ok := options.Fallback.(*roundtripper); ok {
		options.RequestProxy = base.requestProxy
		options.UseResolvedTCPAddresses = clientdialer.IsDefault(base.http1tr.DialContext)
	} else if base, ok := options.Fallback.(*http.Transport); ok {
		options.UseResolvedTCPAddresses = clientdialer.IsDefault(base.DialContext)
	}

	return h3transport.New(options)
}

// ECHClientHelloInner supplies the real QUIC ECH inner ClientHello policy.
// Browser profiles select their policy automatically. Nil restores engine defaults.
func (h *HTTP3Settings) ECHClientHelloInner(policy utls.ECHClientHelloInnerFunc) *HTTP3Settings {
	h.options.ECHClientHelloInner = policy
	return h
}
