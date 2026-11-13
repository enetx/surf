package h3transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"golang.org/x/net/idna"
)

type coalescingPeer struct {
	partition   string
	origin      string
	destination string
	excluded    bool
	origins     map[string]struct{}
}

type coalescingRetryKey struct{}

type coalescingPartitionKey struct{}
type coalescingPartition struct {
	authority, value string
	mu               sync.Mutex
	lookups          map[string]*coalescingAddressResult
}

type coalescingAddressResult struct {
	once      sync.Once
	addresses []net.IPAddr
	err       error
}

// Each instance belongs to one built client, TLS configuration, resolver and
// proxy route. Surf has no browser top-frame NetworkAnonymizationKey model.
type connectionCoalescer struct {
	enabled      bool
	mu           sync.Mutex
	transport    *Transport
	peers        map[*quic.Conn]*coalescingPeer
	originFrames bool
	ignoreIP     bool
	originLimit  int
	onOrigin     func(*quic.Conn, []string)
	appPartition func(context.Context, string) string
}

func newConnectionCoalescer(transport *Transport, options Options) *connectionCoalescer {
	limit := options.OriginFrameLimit
	if limit == 0 {
		limit = 20
	}

	return &connectionCoalescer{
		enabled:   options.ConnectionCoalescing,
		transport: transport, peers: make(map[*quic.Conn]*coalescingPeer),
		originFrames: options.OriginFrames, ignoreIP: options.IgnoreIPMatching,
		originLimit: limit, onOrigin: options.OnOrigin, appPartition: options.ConnectionPoolPartition,
	}
}

// Caller holds mu. Connection closure drops all learned origin state.
func (c *connectionCoalescer) peer(conn *quic.Conn) *coalescingPeer {
	peer := c.peers[conn]
	if peer == nil {
		peer = &coalescingPeer{origins: make(map[string]struct{})}
		c.peers[conn] = peer
		context.AfterFunc(conn.Context(), func() {
			c.mu.Lock()
			delete(c.peers, conn)
			c.mu.Unlock()
		})
	}

	return peer
}

func (c *connectionCoalescer) track(
	ctx context.Context,
	conn *quic.Conn,
	origin, destination string,
	config *tls.Config,
) {
	if c == nil || conn == nil {
		return
	}

	host, _, _ := net.SplitHostPort(origin)
	partition := c.partition(ctx, origin)

	c.mu.Lock()
	peer := c.peer(conn)
	peer.origin = origin
	peer.partition = partition
	peer.destination = destination
	// Custom application verification has no cross-authority contract. Likewise
	// configured client credentials may carry origin-specific authentication.
	// Keep those connections dedicated rather than bypassing application policy.
	peer.excluded = config.InsecureSkipVerify || len(config.Certificates) != 0 ||
		config.GetClientCertificate != nil || config.VerifyConnection != nil ||
		config.VerifyPeerCertificate != nil || !strings.EqualFold(config.ServerName, host)
	c.mu.Unlock()
}

// Keep discovery invalidation and sticky protocol-race decisions authoritative
// for their own origin. This early probe only adds cross-authority opportunities.
func (c *connectionCoalescer) hasOwnConnection(ctx context.Context, authority string) bool {
	partition := c.partition(ctx, authority)
	c.mu.Lock()
	defer c.mu.Unlock()

	for conn, peer := range c.peers {
		if strings.EqualFold(peer.origin, authority) && peer.partition == partition && conn.Context().Err() == nil {
			return true
		}
	}

	return false
}

// QuicSessionKey keeps DNS-ALPN-only sessions separate from connections whose
// version is already known (Alt-Svc or explicit protocol selection).
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_session_key.cc
func (c *connectionCoalescer) partition(ctx context.Context, authority string) string {
	if frozen, ok := ctx.Value(coalescingPartitionKey{}).(*coalescingPartition); ok && strings.EqualFold(frozen.authority, authority) {
		return frozen.value
	}

	requireDNS := c.transport.discovery != nil && !c.transport.forceHTTP3
	if requireDNS {
		if route, ok := ctx.Value(alternativeRouteKey{}).(alternativeRoute); ok && strings.EqualFold(route.origin, authority) && route.address != "" {
			requireDNS = !route.fromAltSvc
		} else if route, ok := c.transport.discovery.get(authority); ok && route.fromAltSvc {
			requireDNS = false
		}
	}

	partition := "known-h3"
	if requireDNS {
		partition = "dns-h3"
	}

	if c.appPartition != nil {
		partition += "\x00" + c.appPartition(ctx, authority)
	}

	return partition
}

func (c *connectionCoalescer) prepareContext(ctx context.Context, authority string) context.Context {
	if frozen, ok := ctx.Value(coalescingPartitionKey{}).(*coalescingPartition); ok && strings.EqualFold(frozen.authority, authority) {
		return ctx
	}

	// A cached pre-discovery probe still targets the selected alternative, not
	// the origin's default authority. An explicitly supplied empty route (421)
	// suppresses Alt-Svc and must never be replaced here.
	if c.transport.discovery != nil && ctx.Value(alternativeRouteKey{}) == nil {
		if route, ok := c.transport.discovery.get(authority); ok {
			ctx = context.WithValue(ctx, alternativeRouteKey{}, route)
		}
	}

	value := c.partition(ctx, authority)

	return context.WithValue(ctx, coalescingPartitionKey{}, &coalescingPartition{
		authority: authority,
		value:     value,
		lookups:   make(map[string]*coalescingAddressResult),
	})
}

// Chromium FindExistingSession/HasMatchingIpSession always call CanPool, which
// checks TLS identity and the session's isolation key before waiving IP matching.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_session_pool.cc
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/spdy/spdy_session.cc
func (c *connectionCoalescer) canReuse(ctx context.Context, info http3.ConnectionReuseInfo) bool {
	if retried, _ := ctx.Value(coalescingRetryKey{}).(bool); retried {
		return false
	}

	host, _, err := net.SplitHostPort(info.Authority)
	if err != nil || ctx.Err() != nil {
		return false
	}

	state := info.Conn.ConnectionState().TLS
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 ||
		state.PeerCertificates[0].VerifyHostname(host) != nil {
		return false
	}

	destination := info.Authority
	route, routed := ctx.Value(alternativeRouteKey{}).(alternativeRoute)
	if routed && strings.EqualFold(route.origin, info.Authority) && route.address != "" {
		destination = route.address
	} else {
		routed = false
	}

	canonical, err := canonicalCoalescingAuthority(destination, "443")
	if err != nil {
		return false
	}

	c.mu.Lock()
	peer := c.peers[info.Conn]
	if peer == nil || peer.excluded || peer.destination == "" {
		c.mu.Unlock()
		return false
	}

	_, advertised := peer.origins["https://"+canonical]
	sameDestination := strings.EqualFold(peer.destination, destination)
	c.mu.Unlock()

	if sameDestination || c.originFrames && advertised {
		return true
	}

	if c.ignoreIP {
		if options, ok := info.Conn.PeerTransportParameter(0x3128); ok && hasConnectionOption(options, "NOIP") {
			return true
		}
	}
	if !info.AllowNetwork {
		return false
	}
	// Before discovery establishes H3 eligibility, only an existing session's
	// explicit ORIGIN/NOIP authorization can skip DNS and protocol selection.
	if c.transport.discovery != nil && !c.transport.forceHTTP3 && !routed {
		return false
	}

	remoteHost, remotePort, err := net.SplitHostPort(info.Conn.RemoteAddr().String())
	if err != nil {
		return false
	}

	remote, err := netip.ParseAddr(remoteHost)
	if err != nil {
		return false
	}

	targetHost, targetPort, _ := net.SplitHostPort(canonical)
	if targetPort != remotePort {
		return false
	}

	if ip, err := netip.ParseAddr(targetHost); err == nil {
		return ip.Unmap() == remote.Unmap()
	}

	if routed && len(route.hints) > 0 {
		for _, ip := range route.hints {
			if ip.Unmap() == remote.Unmap() {
				return true
			}
		}

		return false
	}

	dialer := c.transport.quicDialer

	lookup := dialer.LookupIPAddr
	if lookup == nil {
		resolver := dialer.NetDialer.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}

		lookup = resolver.LookupIPAddr
	}

	addresses, err := coalescingLookup(ctx, targetHost, lookup)
	if err != nil {
		return false
	}

	for _, address := range addresses {
		if ip, ok := netip.AddrFromSlice(address.IP); ok && ip.Unmap() == remote.Unmap() {
			return true
		}
	}

	return false
}

// One request's candidates use one resolver result, without a persistent DNS
// cache or sharing a failed/cancelled lookup with the next request.
func coalescingLookup(
	ctx context.Context,
	host string,
	lookup func(context.Context, string) ([]net.IPAddr, error),
) ([]net.IPAddr, error) {
	state, ok := ctx.Value(coalescingPartitionKey{}).(*coalescingPartition)
	if !ok {
		return lookup(ctx, host)
	}

	state.mu.Lock()
	result := state.lookups[host]
	if result == nil {
		result = &coalescingAddressResult{}
		state.lookups[host] = result
	}
	state.mu.Unlock()

	result.once.Do(func() { result.addresses, result.err = lookup(ctx, host) })

	return result.addresses, result.err
}

func hasConnectionOption(options []byte, tag string) bool {
	if len(options)%4 != 0 || len(tag) != 4 {
		return false
	}

	for i := 0; i < len(options); i += 4 {
		if string(options[i:i+4]) == tag {
			return true
		}
	}

	return false
}

func (c *connectionCoalescer) controlFrameHandler(
	previous func(*quic.Conn, http3.ControlFrame) error,
) func(*quic.Conn, http3.ControlFrame) error {
	return func(conn *quic.Conn, frame http3.ControlFrame) error {
		if frame.Type != 0xc || !c.originFrames {
			if previous != nil {
				return previous(conn, frame)
			}
			return nil
		}

		return c.readOriginFrame(conn, frame.Payload, frame.Length)
	}
}

// RFC 9412 uses 16-bit origin-entry lengths. Parse incrementally and retain at
// most the configured number of valid origins. Publish only a complete frame.
// https://www.rfc-editor.org/rfc/rfc9412.html#section-2
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_chromium_client_session.cc
func (c *connectionCoalescer) readOriginFrame(conn *quic.Conn, payload io.Reader, remaining uint64) error {
	c.mu.Lock()
	known := make(map[string]struct{})
	if peer := c.peers[conn]; peer != nil {
		for origin := range peer.origins {
			known[origin] = struct{}{}
		}
	}
	c.mu.Unlock()

	var added []string
	for remaining > 0 {
		if remaining < 2 {
			return io.ErrUnexpectedEOF
		}

		var length [2]byte
		if _, err := io.ReadFull(payload, length[:]); err != nil {
			return err
		}

		remaining -= 2

		n := int64(binary.BigEndian.Uint16(length[:]))
		if uint64(n) > remaining {
			return io.ErrUnexpectedEOF
		}

		remaining -= uint64(n)

		if len(known) >= c.originLimit {
			if _, err := io.CopyN(io.Discard, payload, n); err != nil {
				return err
			}
			continue
		}

		entry := make([]byte, int(n))
		if _, err := io.ReadFull(payload, entry); err != nil {
			return err
		}

		origin, ok := parseAdvertisedOrigin(string(entry))
		if !ok {
			continue
		}

		if _, exists := known[origin]; !exists {
			known[origin] = struct{}{}
			added = append(added, origin)
		}
	}

	if len(added) == 0 || conn.Context().Err() != nil {
		return nil
	}

	c.mu.Lock()
	peer := c.peer(conn)
	for _, origin := range added {
		peer.origins[origin] = struct{}{}
	}
	c.mu.Unlock()

	if c.onOrigin != nil {
		c.onOrigin(conn, added)
	}

	return nil
}

func parseAdvertisedOrigin(raw string) (string, bool) {
	// Chromium appends '/' and accepts an entry only if GURL's path is '/'.
	u, err := url.Parse(raw + "/")
	if err != nil || u.Path != "/" || u.Opaque != "" || u.Host == "" {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	port := ""
	switch scheme {
	case "https", "wss":
		port = "443"
	case "http", "ws":
		port = "80"
	case "ftp":
		port = "21"
	default:
		return "", false
	}

	authority, err := canonicalCoalescingAuthority(u.Host, port)

	return scheme + "://" + authority, err == nil
}

func canonicalCoalescingAuthority(authority, defaultPort string) (string, error) {
	u, err := url.Parse("https://" + authority)
	if err != nil {
		return "", err
	}

	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
	} else {
		host, err = idna.Lookup.ToASCII(strings.ToLower(host))
		if err != nil || host == "" {
			return "", &url.Error{Op: "parse", URL: authority, Err: net.InvalidAddrError("invalid authority")}
		}
	}

	port := u.Port()
	if port == "" {
		port = defaultPort
	}

	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(host, strconv.FormatUint(n, 10)), nil
}
