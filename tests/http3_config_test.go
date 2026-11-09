package surf_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/surf"
	"github.com/quic-go/qpack"
	"github.com/wzshiming/socks5"
)

type (
	h3Setting        struct{ id, value uint64 }
	h3RequestCapture struct {
		settings []h3Setting
		headers  []qpack.HeaderField
	}
)
type h3InitialCapture struct {
	version               uint32
	size, sourceCIDLength int
}

// Read the unencrypted Initial header directly. Transport parameters are
// independently checked after the receiving QUIC endpoint decodes them.
type h3CaptureConn struct {
	net.PacketConn
	mu          sync.Mutex
	initials    []h3InitialCapture
	rawInitials [][]byte
}

func (c *h3CaptureConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil && n >= 7 && b[0]&0xf0 == 0xc0 && binary.BigEndian.Uint32(b[1:5]) == 1 {
		sourcePos := 6 + int(b[5])
		if sourcePos < n {
			c.mu.Lock()
			c.rawInitials = append(c.rawInitials, bytes.Clone(b[:n]))
			c.initials = append(c.initials, h3InitialCapture{version: 1, size: n, sourceCIDLength: int(b[sourcePos])})
			c.mu.Unlock()
		}
	}
	return n, addr, err
}

type h3Peer struct {
	qpackCapacity *uint64
	qpackStreams  chan h3QPACKCapture
	packet        *h3CaptureConn
	mu            sync.Mutex
	parameters    []qlog.ParametersSet
	priorities    []qlog.StreamPriorityUpdated
	versions      []quic.Version
	resumed       []bool
	requests      chan h3RequestCapture
	errors        chan error
	url           string
}

func (p *h3Peer) AddProducer() qlogwriter.Recorder { return p }
func (p *h3Peer) Close() error                     { return nil }
func (p *h3Peer) RecordEvent(event qlogwriter.Event) {
	if e, ok := event.(qlog.StreamPriorityUpdated); ok {
		p.mu.Lock()
		p.priorities = append(p.priorities, e)
		p.mu.Unlock()
	}
	if e, ok := event.(qlog.ParametersSet); ok && e.Initiator == qlog.InitiatorRemote {
		p.mu.Lock()
		p.parameters = append(p.parameters, e)
		p.mu.Unlock()
	}
}

func newH3Peer(t *testing.T) *h3Peer {
	return newH3PeerWithQPACK(t, nil)
}

func newH3PeerWithQPACK(t *testing.T, capacity *uint64) *h3Peer {
	t.Helper()
	s, udp, _, err := createHTTP3TestServer(func(w http.ResponseWriter, r *http.Request) {})
	if err != nil {
		t.Fatal(err)
	}
	p := &h3Peer{
		packet:   &h3CaptureConn{PacketConn: udp},
		requests: make(chan h3RequestCapture, 16),
		errors:   make(chan error, 16),
	}
	if capacity != nil {
		p.qpackCapacity = new(*capacity)
		p.qpackStreams = make(chan h3QPACKCapture, 4)
	}
	transport := &quic.Transport{Conn: p.packet}
	config := &quic.Config{
		EnableDatagrams: true, EnableStreamResetPartialDelivery: true,
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return p },
	}
	listener, err := transport.Listen(s.TLSConfig, config)
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); listener.Close(); transport.Close(); udp.Close() })
	p.url = "https://" + udp.LocalAddr().String()
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			go p.serve(ctx, conn)
		}
	}()
	return p
}

func (p *h3Peer) fail(err error) {
	select {
	case p.errors <- err:
	default:
	}
}

func (p *h3Peer) serve(ctx context.Context, conn *quic.Conn) {
	p.mu.Lock()
	p.versions = append(p.versions, conn.ConnectionState().Version)
	p.resumed = append(p.resumed, conn.ConnectionState().TLS.DidResume)
	p.mu.Unlock()
	control, err := conn.OpenUniStream()
	if err != nil {
		p.fail(err)
		return
	}
	var payload []byte
	if p.qpackCapacity != nil {
		payload = quicvarint.Append(quicvarint.Append(nil, 1), *p.qpackCapacity)
	}
	settingsFrame := quicvarint.Append([]byte{0, 4}, uint64(len(payload)))
	settingsFrame = append(settingsFrame, payload...)
	if _, err := control.Write(settingsFrame); err != nil {
		p.fail(err)
		return
	}
	settingsReady := make(chan struct{})
	var settings []h3Setting
	go func() {
		for {
			stream, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go func() {
				r := quicvarint.NewReader(stream)
				typ, err := quicvarint.Read(r)
				if err != nil {
					p.fail(err)
					return
				}
				if typ != 0 {
					if p.qpackStreams != nil {
						select {
						case p.qpackStreams <- h3QPACKCapture{typ, stream.StreamID(), stream, r}:
						case <-ctx.Done():
						}
						return
					}
					io.Copy(io.Discard, stream)
					return
				}
				frame, err := quicvarint.Read(r)
				if err != nil || frame != 4 {
					p.fail(fmt.Errorf("first control frame = %d: %v", frame, err))
					return
				}
				length, err := quicvarint.Read(r)
				if err != nil || length > 8192 {
					p.fail(fmt.Errorf("settings size = %d: %v", length, err))
					return
				}
				buf := make([]byte, int(length))
				if _, err := io.ReadFull(stream, buf); err != nil {
					p.fail(err)
					return
				}
				b := bytes.NewReader(buf)
				for b.Len() > 0 {
					id, err := quicvarint.Read(b)
					if err != nil {
						p.fail(err)
						return
					}
					value, err := quicvarint.Read(b)
					if err != nil {
						p.fail(err)
						return
					}
					settings = append(settings, h3Setting{id, value})
				}
				close(settingsReady)
				io.Copy(io.Discard, stream)
			}()
		}
	}()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			stream.SetReadDeadline(time.Now().Add(5 * time.Second))
			r := quicvarint.NewReader(stream)
			typ, err := quicvarint.Read(r)
			if err != nil || typ != 1 {
				p.fail(fmt.Errorf("first request frame = %d: %v", typ, err))
				return
			}
			length, err := quicvarint.Read(r)
			if err != nil || length > 1<<20 {
				p.fail(fmt.Errorf("header size = %d: %v", length, err))
				return
			}
			buf := make([]byte, int(length))
			if _, err := io.ReadFull(stream, buf); err != nil {
				p.fail(err)
				return
			}
			decode := qpack.NewDecoder().Decode(buf)
			var headers []qpack.HeaderField
			for {
				field, err := decode()
				if err == io.EOF {
					break
				}
				if err != nil {
					p.fail(err)
					return
				}
				headers = append(headers, field)
			}
			select {
			case <-settingsReady:
			case <-ctx.Done():
				return
			case <-conn.Context().Done():
				return
			}
			p.requests <- h3RequestCapture{settings: slices.Clone(settings), headers: headers}
			var block bytes.Buffer
			enc := qpack.NewEncoder(&block)
			if err := enc.WriteField(qpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
				p.fail(err)
				return
			}
			enc.Close()
			response := quicvarint.Append(nil, 1)
			response = quicvarint.Append(response, uint64(block.Len()))
			response = append(response, block.Bytes()...)
			response = append(response, 0, 2, 'o', 'k')
			if _, err := stream.Write(response); err != nil {
				p.fail(err)
			}
		}()
	}
}

func (p *h3Peer) request(t *testing.T, client *surf.Client) h3RequestCapture {
	t.Helper()
	response := client.Get(g.String(p.url + "/wire")).Do()
	if response.IsErr() {
		select {
		case err := <-p.errors:
			t.Fatalf("request: %v; peer: %v", response.Err(), err)
		default:
			t.Fatal(response.Err())
		}
	}
	if response.Ok().GetResponse().ProtoMajor != 3 {
		t.Fatal("request fell back from HTTP/3")
	}
	body := response.Ok().Body.String()
	if body.IsErr() || body.Ok() != "ok" {
		t.Fatalf("body = %v", body)
	}
	select {
	case got := <-p.requests:
		return got
	case err := <-p.errors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("no request capture")
	}
	return h3RequestCapture{}
}

func TestHTTP3NativeConfigurationOnWire(t *testing.T) {
	for _, cid := range []int{0, 8} {
		t.Run(fmt.Sprintf("cid-%d", cid), func(t *testing.T) {
			peer := newH3Peer(t)
			clientTrace := new(h3Peer)
			config := &quic.Config{
				Versions:                   []quic.Version{quic.Version1},
				InitialStreamReceiveWindow: 128 << 10, MaxStreamReceiveWindow: 128 << 10,
				InitialConnectionReceiveWindow: 2 << 20, MaxConnectionReceiveWindow: 2 << 20,
				MaxIncomingStreams: 7, MaxIncomingUniStreams: 11,
				MaxIdleTimeout: 24 * time.Second, InitialPacketSize: 1350,
				DisablePathMTUDiscovery: true, EnableStreamResetPartialDelivery: true,
				Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return clientTrace },
			}
			extra := g.NewMapOrd[uint64, uint64]()
			extra.Insert(0x2a2a, 42)
			builder := surf.NewClient().Builder().ForceHTTP3()
			headers := g.NewMapOrd[string, string]()
			for _, name := range []string{":path", ":method", ":authority", ":scheme"} {
				headers.Insert(name, "")
			}
			headers.Insert("X-Z", "last")
			headers.Insert("X-A", "first")
			headers.Insert("User-Agent", "wire-test")
			builder.SetHeaders(headers)
			h := builder.HTTP3Settings().QUICConfig(config).ConnectionIDLength(cid).
				QpackMaxTableCapacity(0).EnableDatagrams(true).QpackBlockedStreams(0).
				AdditionalSettings(extra).StreamPriority(1, true)
			config.InitialConnectionReceiveWindow = 99
			config.Versions[0] = quic.Version2
			extra.Insert(0x2a2a, 99)
			client := h.Set().Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			got := peer.request(t, client)
			want := []h3Setting{{1, 0}, {0x33, 1}, {7, 0}, {0x2a2a, 42}}
			if !slices.Equal(got.settings, want) {
				t.Fatalf("settings = %v, want %v", got.settings, want)
			}
			for _, header := range got.headers {
				if strings.Contains(header.Name, "header-order") {
					t.Fatalf("metadata reached wire: %+v", header)
				}
			}
			var names []string
			for _, field := range got.headers {
				names = append(names, field.Name)
			}
			if len(names) < 7 ||
				!slices.Equal(
					names[:7],
					[]string{":path", ":method", ":authority", ":scheme", "x-z", "x-a", "user-agent"},
				) {
				t.Fatalf("QPACK header order = %v", names)
			}
			clientTrace.mu.Lock()
			priorities := slices.Clone(clientTrace.priorities)
			clientTrace.mu.Unlock()
			if len(priorities) != 1 || priorities[0].StreamID != 0 || priorities[0].Urgency != 1 ||
				!priorities[0].Incremental {
				t.Fatalf("local stream priorities = %+v", priorities)
			}
			peer.mu.Lock()
			parameters := slices.Clone(peer.parameters)
			peer.mu.Unlock()
			if len(parameters) != 1 {
				t.Fatalf("parameters = %+v", parameters)
			}
			p := parameters[0]
			if p.InitialMaxData != 2<<20 || p.InitialMaxStreamDataBidiLocal != 128<<10 ||
				p.InitialMaxStreamsBidi != 7 ||
				p.InitialMaxStreamsUni != 11 ||
				p.MaxIdleTimeout != 24*time.Second ||
				!p.EnableResetStreamAt ||
				p.MaxDatagramFrameSize <= 0 {
				t.Fatalf("peer parameters = %+v", p)
			}
			peer.packet.mu.Lock()
			if len(peer.packet.initials) == 0 {
				peer.packet.mu.Unlock()
				t.Fatal("no Initial packet")
			}
			initial := peer.packet.initials[0]
			peer.packet.mu.Unlock()
			if initial.version != 1 || initial.sourceCIDLength != cid || initial.size != 1350 {
				t.Fatalf("Initial = %+v", initial)
			}
		})
	}
}

func TestHTTP3ZeroCIDAcrossOrigins(t *testing.T) {
	a, b := newH3Peer(t), newH3Peer(t)
	client := surf.NewClient().
		Builder().
		ForceHTTP3().
		HTTP3Settings().
		ConnectionIDLength(0).
		Set().
		Timeout(5 * time.Second).
		Build().
		Unwrap()
	defer client.Close()
	for _, peer := range []*h3Peer{a, b, a, b} {
		peer.request(t, client)
	}
	for _, peer := range []*h3Peer{a, b} {
		peer.mu.Lock()
		count := len(peer.parameters)
		peer.mu.Unlock()
		if count != 1 {
			t.Fatalf("origin used %d connections, want one reused connection", count)
		}
		peer.packet.mu.Lock()
		initial := peer.packet.initials[0]
		peer.packet.mu.Unlock()
		if initial.sourceCIDLength != 0 {
			t.Fatalf("SCID length = %d", initial.sourceCIDLength)
		}
	}
	client.CloseIdleConnections()
	a.request(t, client)
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.parameters) != 2 {
		t.Fatalf("new connection after closing idle: %d", len(a.parameters))
	}
}

func TestHTTP3ConfigValidationAndReset(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*surf.HTTP3Settings)
	}{
		{"negative-cid", func(h *surf.HTTP3Settings) { h.ConnectionIDLength(-1) }},
		{"long-cid", func(h *surf.HTTP3Settings) { h.ConnectionIDLength(21) }},
		{"invalid-generator", func(h *surf.HTTP3Settings) { h.ConnectionIDGenerator(sizedCIDGenerator{21}) }},
		{"negative-header-limit", func(h *surf.HTTP3Settings) { h.MaxResponseHeaderBytes(-1) }},
		{"datagram-mismatch", func(h *surf.HTTP3Settings) { h.QUICConfig(&quic.Config{}).SettingsH3Datagram(1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := surf.NewClient().Builder().ForceHTTP3().HTTP3Settings()
			tc.configure(h)
			if result := h.Set().Build(); result.IsOk() {
				result.Ok().Close()
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	peer := newH3Peer(t)
	client := surf.NewClient().
		Builder().
		ForceHTTP3().
		HTTP3Settings().
		QUICConfig(&quic.Config{InitialConnectionReceiveWindow: 99}).
		QUICConfig(nil).
		Set().
		Build().
		Unwrap()
	defer client.Close()
	peer.request(t, client)
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.parameters[0].InitialMaxData == 99 {
		t.Fatal("QUICConfig(nil) did not restore defaults")
	}
	if peer.parameters[0].InitialSourceConnectionID.Len() != 4 {
		t.Fatal("unset CID did not retain official default")
	}
}

func TestHTTP3NativeConfigurationViaSOCKS5(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	proxy := socks5.NewServer()
	proxy.Context = ctx
	proxy.ProxyListenPacket = func(context.Context, string, string) (net.PacketConn, error) {
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}
	go proxy.Serve(listener)
	for _, cid := range []int{0, 8} {
		t.Run(fmt.Sprint(cid), func(t *testing.T) {
			peer := newH3Peer(t)
			client := surf.NewClient().
				Builder().
				Proxy(g.String("socks5://" + listener.Addr().String())).
				ForceHTTP3().
				HTTP3Settings().
				QUICConfig(&quic.Config{InitialConnectionReceiveWindow: 2 << 20, InitialPacketSize: 1350}).
				ConnectionIDLength(cid).
				Set().
				Timeout(5 * time.Second).
				Build().
				Unwrap()
			defer client.Close()
			peer.request(t, client)
			peer.mu.Lock()
			parameters := peer.parameters[0]
			peer.mu.Unlock()
			if parameters.InitialMaxData != 2<<20 {
				t.Fatalf("proxy dropped connection window: %+v", parameters)
			}
			peer.packet.mu.Lock()
			initial := peer.packet.initials[0]
			peer.packet.mu.Unlock()
			if initial.sourceCIDLength != cid || initial.size != 1350 {
				t.Fatalf("proxy Initial = %+v", initial)
			}
		})
	}
}

func TestHTTP3DatagramLayersAndCompression(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			peer := newH3Peer(t)
			builder := surf.NewClient().Builder().ForceHTTP3()
			if !enabled {
				builder.DisableCompression()
			}
			client := builder.HTTP3Settings().EnableDatagrams(enabled).Set().Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			capture := peer.request(t, client)
			if !slices.Equal(capture.settings, []h3Setting{{0x33, map[bool]uint64{false: 0, true: 1}[enabled]}}) {
				t.Fatalf("settings = %v", capture.settings)
			}
			peer.mu.Lock()
			datagrams := peer.parameters[0].MaxDatagramFrameSize > 0
			peer.mu.Unlock()
			if datagrams != enabled {
				t.Fatalf("QUIC datagrams = %v", datagrams)
			}
			gzip := false
			for _, field := range capture.headers {
				if field.Name == "accept-encoding" && field.Value == "gzip" {
					gzip = true
				}
			}
			if gzip != enabled {
				t.Fatalf("automatic compression = %v", gzip)
			}
		})
	}
}

func TestHTTP3ResponseHeaderLimit(t *testing.T) {
	peer := newH3Peer(t)
	client := surf.NewClient().
		Builder().
		ForceHTTP3().
		HTTP3Settings().
		MaxResponseHeaderBytes(1).
		Set().
		Timeout(5 * time.Second).
		Build().
		Unwrap()
	defer client.Close()
	response := client.Get(g.String(peer.url)).Do()
	if response.IsOk() {
		t.Fatal("oversized headers accepted")
	}
	if !strings.Contains(response.Err().Error(), "HEADERS frame too large") {
		t.Fatalf("error = %v", response.Err())
	}
}

func TestHTTP3QUICVersion2(t *testing.T) {
	peer := newH3Peer(t)
	client := surf.NewClient().
		Builder().
		ForceHTTP3().
		HTTP3Settings().
		QUICConfig(&quic.Config{Versions: []quic.Version{quic.Version2}}).
		Set().
		Timeout(5 * time.Second).
		Build().
		Unwrap()
	defer client.Close()
	peer.request(t, client)
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if !slices.Equal(peer.versions, []quic.Version{quic.Version2}) {
		t.Fatalf("negotiated versions = %v", peer.versions)
	}
}

type sizedCIDGenerator struct{ length int }

func (g sizedCIDGenerator) ConnectionIDLen() int { return g.length }
func (g sizedCIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	buf := make([]byte, g.length)
	if _, err := rand.Read(buf); err != nil {
		return quic.ConnectionID{}, err
	}
	return quic.ConnectionIDFromBytes(buf), nil
}

func TestHTTP3ConnectionIDGenerator(t *testing.T) {
	peer := newH3Peer(t)
	client := surf.NewClient().
		Builder().
		ForceHTTP3().
		HTTP3Settings().
		ConnectionIDLength(4).
		ConnectionIDGenerator(sizedCIDGenerator{6}).
		Set().
		Timeout(5 * time.Second).
		Build().
		Unwrap()
	defer client.Close()
	peer.request(t, client)
	peer.packet.mu.Lock()
	defer peer.packet.mu.Unlock()
	if peer.packet.initials[0].sourceCIDLength != 6 {
		t.Fatalf("generator was not used: %+v", peer.packet.initials[0])
	}
}

func TestBrowserHTTP3SupportedParameters(t *testing.T) {
	for _, tc := range []struct {
		name               string
		cid                int
		stream, connection uint64
		bidi, uni          int64
	}{
		{"chrome-desktop", 0, 6 << 20, 15 << 20, 100, 103},
		{"chrome-android", 0, 6 << 20, 15 << 20, 100, 103},
		{"firefox-desktop", 3, 1 << 20, 24 << 20, 100, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newH3Peer(t)
			im := surf.NewClient().Builder().Impersonate().Windows()
			if tc.name == "chrome-android" {
				im.Android()
			}
			var builder *surf.Builder
			if strings.HasPrefix(tc.name, "firefox") {
				builder = im.Firefox()
			} else {
				builder = im.Chrome()
			}
			client := builder.ForceHTTP3().Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			capture := peer.request(t, client)
			if len(capture.settings) < 3 {
				t.Fatalf("browser settings missing: %v", capture.settings)
			}
			var datagrams int
			for _, setting := range capture.settings {
				if setting.id == 0x33 && setting.value == 1 {
					datagrams++
				}
			}
			if datagrams != 1 {
				t.Fatalf("H3_DATAGRAM count = %d, settings = %v", datagrams, capture.settings)
			}
			var settings []h3Setting
			for _, setting := range capture.settings {
				if setting.id >= 0x21 && (setting.id-0x21)%0x1f == 0 {
					setting = h3Setting{0x21, 0}
				}
				settings = append(settings, setting)
			}
			wantSettings := []h3Setting{{1, 65536}, {6, 262144}, {7, 100}, {0x33, 1}, {0x21, 0}}
			wantHeaders := []string{
				":method",
				":authority",
				":scheme",
				":path",
				"sec-ch-ua",
				"sec-ch-ua-mobile",
				"sec-ch-ua-platform",
				"upgrade-insecure-requests",
				"user-agent",
				"accept",
				"sec-fetch-site",
				"sec-fetch-mode",
				"sec-fetch-user",
				"sec-fetch-dest",
				"accept-encoding",
				"accept-language",
				"priority",
			}
			if strings.HasPrefix(tc.name, "firefox") {
				wantSettings = []h3Setting{{1, 65536}, {7, 20}, {0x2b603742, 0}, {0xffd277, 1}, {0x33, 1}, {8, 1}}
				wantHeaders = []string{
					":method",
					":scheme",
					":authority",
					":path",
					"user-agent",
					"accept",
					"accept-language",
					"accept-encoding",
					"alt-used",
					"upgrade-insecure-requests",
					"sec-fetch-dest",
					"sec-fetch-mode",
					"sec-fetch-site",
					"sec-fetch-user",
					"priority",
				}
			}
			if !slices.Equal(settings, wantSettings) {
				t.Fatalf("browser settings order = %v, want %v", settings, wantSettings)
			}
			var names []string
			for _, header := range capture.headers {
				names = append(names, header.Name)
			}
			if !slices.Equal(names, wantHeaders) {
				t.Fatalf("browser QPACK header order = %v, want %v", names, wantHeaders)
			}
			peer.mu.Lock()
			parameters := peer.parameters[0]
			peer.mu.Unlock()
			localWindow := tc.stream
			if tc.name == "firefox-desktop" {
				localWindow = 12 << 20
			}
			if uint64(parameters.InitialMaxData) != tc.connection ||
				uint64(parameters.InitialMaxStreamDataBidiLocal) != localWindow ||
				uint64(parameters.InitialMaxStreamDataBidiRemote) != tc.stream ||
				uint64(parameters.InitialMaxStreamDataUni) != tc.stream ||
				parameters.InitialMaxStreamsBidi != tc.bidi ||
				parameters.InitialMaxStreamsUni != tc.uni {
				t.Fatalf("browser parameters = %+v", parameters)
			}
			peer.packet.mu.Lock()
			initial := peer.packet.initials[0]
			peer.packet.mu.Unlock()
			if initial.sourceCIDLength != tc.cid {
				t.Fatalf("SCID = %d, want %d", initial.sourceCIDLength, tc.cid)
			}
		})
	}
}

func TestHTTP3OverridesPreserveBrowserSettings(t *testing.T) {
	peer := newH3Peer(t)
	builder := surf.NewClient().Builder().Impersonate().Windows().Chrome().ForceHTTP3()
	config := &quic.Config{Versions: []quic.Version{quic.Version1}, InitialPacketSize: 1350, EnableDatagrams: true}
	client := builder.HTTP3Settings().QUICConfig(config).Set().Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	got := peer.request(t, client)
	if len(got.settings) < 3 || got.settings[0] != (h3Setting{1, 65536}) {
		t.Fatalf("profile settings lost: %v", got.settings)
	}
	peer.packet.mu.Lock()
	defer peer.packet.mu.Unlock()
	initial := peer.packet.initials[0]
	if initial.size != 1350 || initial.sourceCIDLength != 0 {
		t.Fatalf("override lost profile CID or packet size: %+v", initial)
	}
}

func TestHTTP3ProfileReplacementDoesNotMergeSettings(t *testing.T) {
	peer := newH3Peer(t)
	builder := surf.NewClient().Builder().Impersonate().Windows().Chrome()
	client := builder.Impersonate().Windows().Firefox().ForceHTTP3().Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	got := peer.request(t, client)
	want := []h3Setting{{1, 65536}, {7, 20}, {0x2b603742, 0}, {0xffd277, 1}, {0x33, 1}, {8, 1}}
	if !slices.Equal(got.settings, want) {
		t.Fatalf("previous H3 profile remained: %v", got.settings)
	}
	peer.packet.mu.Lock()
	defer peer.packet.mu.Unlock()
	if peer.packet.initials[0].sourceCIDLength != 3 {
		t.Fatal("previous profile CID remained")
	}
}
