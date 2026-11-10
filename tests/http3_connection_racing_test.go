package surf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf"
	chromecommon "github.com/enetx/surf/profiles/chrome/common"
	firefoxcommon "github.com/enetx/surf/profiles/firefox/common"
	"github.com/stretchr/testify/require"
	"github.com/wzshiming/socks5"
)

type racingUDP struct {
	net.PacketConn
	enabled atomic.Bool
	once    sync.Once
	seen    chan struct{}
}

func (c *racingUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, a, e := c.PacketConn.ReadFrom(p)
		if e != nil {
			return n, a, e
		}
		c.once.Do(func() { close(c.seen) })
		if c.enabled.Load() {
			return n, a, nil
		}
	}
}
func (c *racingUDP) WriteTo(p []byte, a net.Addr) (int, error) {
	if !c.enabled.Load() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, a)
}

type racingObservation struct {
	protocol int
	body     string
	header   http.Header
}
type racingPeer struct {
	url                 string
	udp                 *racingUDP
	tcpHello            chan struct{}
	tcpGate             chan struct{}
	observed            chan racingObservation
	tcpCalls, quicCalls atomic.Int32
	tcpConnections      atomic.Int32
	tcp                 *httptest.Server
	quic                *http3.Server
}

func newRacingPeer(t *testing.T, h2, udpEnabled, tcpBlocked bool) *racingPeer {
	t.Helper()
	p := &racingPeer{tcpHello: make(chan struct{}, 64), tcpGate: make(chan struct{}), observed: make(chan racingObservation, 128)}
	if !tcpBlocked {
		close(p.tcpGate)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		if r.ProtoMajor == 3 {
			p.quicCalls.Add(1)
		} else {
			p.tcpCalls.Add(1)
		}
		p.observed <- racingObservation{r.ProtoMajor, string(body), r.Header.Clone()}
		if r.URL.Path == "/abort" && r.ProtoMajor == 3 {
			panic(http.ErrAbortHandler)
		}
		if r.URL.Path == "/slow-response" {
			<-r.Context().Done()
			return
		}
		io.WriteString(w, "ok")
	})
	p.tcp = httptest.NewUnstartedServer(handler)
	p.tcp.EnableHTTP2 = h2
	p.tcp.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			p.tcpConnections.Add(1)
		}
	}
	p.tcp.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		p.tcpHello <- struct{}{}
		select {
		case <-p.tcpGate:
			return nil, nil
		case <-t.Context().Done():
			return nil, context.Canceled
		}
	}}
	udp := reserveRacingUDP(t, p.tcp)
	p.tcp.StartTLS()
	p.url = p.tcp.URL
	p.udp = &racingUDP{PacketConn: udp, seen: make(chan struct{})}
	p.udp.enabled.Store(udpEnabled)
	p.quic = &http3.Server{TLSConfig: p.tcp.TLS.Clone(), Handler: handler}
	// Only block the TCP handshake; QUIC must have an independent readiness path.
	p.quic.TLSConfig.GetConfigForClient = nil
	p.quic.TLSConfig.NextProtos = []string{"h3"}
	go p.quic.Serve(p.udp)
	t.Cleanup(func() { p.quic.Close(); udp.Close(); p.tcp.Close() })
	return p
}

// TCP and UDP have independent ephemeral-port namespaces. Reserve both before
// starting the peer; another parallel test can already own UDP N.
func reserveRacingUDP(t *testing.T, server *httptest.Server) net.PacketConn {
	t.Helper()
	var udp net.PacketConn
	var err error
	for attempts := 0; attempts < 32; attempts++ {
		udp, err = net.ListenPacket("udp4", server.Listener.Addr().String())
		if err == nil || !errors.Is(err, syscall.EADDRINUSE) || attempts == 31 {
			break
		}
		server.Listener.Close()
		server.Listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			break
		}
	}
	if err != nil && server.Listener != nil {
		server.Close()
	}
	require.NoError(t, err)
	return udp
}

func TestConnectionRacingPeerReservesBothPortNamespaces(t *testing.T) {
	busy, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()
	listener, err := net.Listen("tcp4", busy.LocalAddr().String())
	if errors.Is(err, syscall.EADDRINUSE) {
		t.Skip("the deliberately occupied UDP port also has an unrelated TCP owner")
	}
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(nil)
	server.Listener.Close()
	server.Listener = listener
	defer server.Close()
	udp := reserveRacingUDP(t, server)
	defer udp.Close()
	require.Equal(t, server.Listener.Addr().String(), udp.LocalAddr().String())
	require.NotEqual(t, busy.LocalAddr().String(), udp.LocalAddr().String())
}

type racingBody struct {
	data          *strings.Reader
	bytes, closes atomic.Int32
}

func (b *racingBody) Read(p []byte) (int, error) {
	n, e := b.data.Read(p)
	b.bytes.Add(int32(n))
	return n, e
}
func (b *racingBody) Close() error { b.closes.Add(1); return nil }

func racingBuilder(browser string) *surf.Builder {
	b := surf.NewClient().Builder()
	if browser == "firefox" {
		b = b.Impersonate().Windows().Firefox()
	}
	if browser == "chrome" {
		b = b.Impersonate().Windows().Chrome()
	}
	return b.ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true}).Timeout(3 * time.Second)
}
func waitRacingSignal(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("missing connection signal")
	}
}

func TestHTTP3ConnectionRacingDoesNotTouchStreamingPOSTBeforeSelection(t *testing.T) {
	for _, browser := range []string{"native", "chrome", "firefox"} {
		for _, h2 := range []bool{true, false} {
			t.Run(browser+map[bool]string{true: "/h2", false: "/h1"}[h2], func(t *testing.T) {
				p := newRacingPeer(t, h2, false, true)
				b := racingBuilder(browser)
				b.QUICSettings().HandshakeIdleTimeout(time.Second).Set()
				h := b.HTTP3Settings().ConnectionRacing(true).TCPFallbackDelay(0)
				client := h.Set().Build().Unwrap()
				defer client.Close()
				// Build freezes both enablement and delay policy.
				h.ConnectionRacing(false).TCPFallbackDelay(-time.Second)
				body := &racingBody{data: strings.NewReader("streamed exactly once")}
				done := make(chan error, 1)
				go func() {
					result := client.Post(g.String(p.url)).StreamingBody(body).Do()
					if result.IsErr() {
						done <- result.Err()
						return
					}
					done <- result.Ok().Body.String().Err()
				}()
				waitRacingSignal(t, p.udp.seen)
				waitRacingSignal(t, p.tcpHello)
				require.Zero(t, body.bytes.Load())
				require.Zero(t, body.closes.Load())
				require.Zero(t, p.tcpCalls.Load())
				require.Zero(t, p.quicCalls.Load())
				close(p.tcpGate)
				require.NoError(t, <-done)
				got := <-p.observed
				want := 1
				if h2 {
					want = 2
				}
				require.Equal(t, want, got.protocol)
				require.Equal(t, "streamed exactly once", got.body)
				require.EqualValues(t, len(got.body), body.bytes.Load())
				require.Eventually(t, func() bool { return body.closes.Load() == 1 }, time.Second, time.Millisecond)
				require.Zero(t, p.quicCalls.Load())
				require.EqualValues(t, 1, p.tcpCalls.Load())
				if browser == "firefox" {
					require.Empty(t, got.header.Get("Alt-Used"))
					if h2 {
						require.Equal(t, "trailers", got.header.Get("TE"))
					} else {
						require.Empty(t, got.header.Get("TE"))
					}
				}
			})
		}
	}
}

func TestHTTP3ConnectionRacingQUICWinnerAndApplicationError(t *testing.T) {
	for _, path := range []string{"/", "/abort"} {
		t.Run(path, func(t *testing.T) {
			p := newRacingPeer(t, true, true, false)
			client := racingBuilder("firefox").HTTP3Settings().ConnectionRacing(true).TCPFallbackDelay(time.Hour).Set().Build().Unwrap()
			defer client.Close()
			body := &racingBody{data: strings.NewReader("no cross-protocol replay")}
			result := client.Post(g.String(p.url + path)).StreamingBody(body).Do()
			if path == "/abort" {
				require.True(t, result.IsErr())
			} else {
				require.False(t, result.IsErr(), "%v", result.Err())
				require.Equal(t, 3, result.Ok().GetResponse().ProtoMajor)
				require.Equal(t, g.String("ok"), result.Ok().Body.String().Unwrap())
			}
			require.Zero(t, p.tcpConnections.Load())
			require.Zero(t, p.tcpCalls.Load())
			require.EqualValues(t, 1, p.quicCalls.Load())
			require.EqualValues(t, len("no cross-protocol replay"), body.bytes.Load())
		})
	}
}

func TestHTTP3ConnectionRacingTCPWinnerKeepsQUICForNextRequest(t *testing.T) {
	p := newRacingPeer(t, true, false, false)
	b := racingBuilder("chrome")
	b.QUICSettings().HandshakeIdleTimeout(2 * time.Second).Set()
	var infosMu sync.Mutex
	var infos []surf.ConnectionRacingInfo
	client := b.HTTP3Settings().ConnectionRacing(true).ConnectionRacingPolicy(func(info surf.ConnectionRacingInfo) time.Duration {
		infosMu.Lock()
		infos = append(infos, info)
		infosMu.Unlock()
		return 0
	}).Set().Build().Unwrap()
	defer client.Close()
	first := client.Get(g.String(p.url)).Do().Unwrap()
	require.Equal(t, 2, first.GetResponse().ProtoMajor)
	first.Body.String().Unwrap()
	p.udp.enabled.Store(true)
	// The already-started QUIC handshake can complete without resending request 1.
	require.Eventually(t, func() bool {
		r := client.Get(g.String(p.url)).Do()
		if r.IsErr() {
			return false
		}
		protocol := r.Ok().GetResponse().ProtoMajor
		r.Ok().Body.String().Unwrap()
		return protocol == 3
	}, 2*time.Second, 20*time.Millisecond)
	require.EqualValues(t, 1, p.tcpConnections.Load())
	last := client.Get(g.String(p.url)).Do().Unwrap()
	require.Equal(t, 3, last.GetResponse().ProtoMajor)
	last.Body.String().Unwrap()
	infosMu.Lock()
	defer infosMu.Unlock()
	require.NotEmpty(t, infos)
	require.False(t, infos[0].QUICWorked)
	require.True(t, infos[len(infos)-1].QUICWorked)
	require.Positive(t, infos[len(infos)-1].SmoothedRTT)
}

func TestHTTP3ConnectionRacingCanceledSharedWaiter(t *testing.T) {
	p := newRacingPeer(t, true, false, true)
	b := racingBuilder("firefox")
	b.QUICSettings().HandshakeIdleTimeout(time.Second).Set()
	client := b.HTTP3Settings().ConnectionRacing(true).TCPFallbackDelay(0).Set().Build().Unwrap()
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	body := &racingBody{data: strings.NewReader("canceled")}
	first := make(chan error, 1)
	go func() { first <- client.Post(g.String(p.url)).WithContext(ctx).StreamingBody(body).Do().Err() }()
	waitRacingSignal(t, p.udp.seen)
	waitRacingSignal(t, p.tcpHello)
	secondStarted := make(chan struct{})
	second := make(chan error, 1)
	go func() {
		close(secondStarted)
		r := client.Get(g.String(p.url)).Do()
		if r.IsErr() {
			second <- r.Err()
			return
		}
		r.Ok().Body.String().Unwrap()
		second <- nil
	}()
	<-secondStarted
	// Cancellation is independent even if the second caller reaches selection later.
	cancel()
	require.ErrorIs(t, <-first, context.Canceled)
	require.Zero(t, body.bytes.Load())
	require.EqualValues(t, 1, body.closes.Load())
	close(p.tcpGate)
	require.NoError(t, <-second)
	require.EqualValues(t, 1, p.tcpCalls.Load())
	require.Zero(t, p.quicCalls.Load())
}

func TestHTTP3ConnectionRacingValidationAndProfilePolicies(t *testing.T) {
	for _, delay := range []time.Duration{-1, -time.Second} {
		require.True(t, racingBuilder("native").HTTP3Settings().ConnectionRacing(true).TCPFallbackDelay(delay).Set().Build().IsErr())
	}
	require.True(t, racingBuilder("native").HTTP3Settings().ConnectionRacing(true).EarlyData(true).Set().Build().IsErr())
	require.True(t, racingBuilder("native").DisableKeepAlive().HTTP3Settings().ConnectionRacing(true).Set().Build().IsErr())
	require.Equal(t, 100*time.Millisecond, firefoxcommon.ConnectionRacing(surf.ConnectionRacingInfo{}))
	require.Zero(t, chromecommon.ConnectionRacing(surf.ConnectionRacingInfo{}))
	require.Equal(t, 300*time.Millisecond, chromecommon.ConnectionRacing(surf.ConnectionRacingInfo{QUICWorked: true}))
	require.Equal(t, 30*time.Millisecond, chromecommon.ConnectionRacing(surf.ConnectionRacingInfo{QUICWorked: true, SmoothedRTT: 20 * time.Millisecond}))
	require.Equal(t, 130*time.Millisecond, chromecommon.ConnectionRacingAndroid(surf.ConnectionRacingInfo{QUICWorked: true, SmoothedRTT: 20 * time.Millisecond}))
	require.Zero(t, chromecommon.ConnectionRacingAndroid(surf.ConnectionRacingInfo{}))
	require.Zero(t, chromecommon.ConnectionRacing(surf.ConnectionRacingInfo{QUICWorked: true, LastQUICError: errors.New("failed")}))
	p := newRacingPeer(t, true, false, false)
	client := racingBuilder("native").HTTP3Settings().ConnectionRacing(true).ConnectionRacingPolicy(func(surf.ConnectionRacingInfo) time.Duration { return -1 }).Set().Build().Unwrap()
	defer client.Close()
	body := &racingBody{data: strings.NewReader("unread")}
	result := client.Post(g.String(p.url)).StreamingBody(body).Do()
	require.True(t, result.IsErr())
	require.ErrorContains(t, result.Err(), "negative TCP")
	require.Zero(t, body.bytes.Load())
	require.EqualValues(t, 1, body.closes.Load())
	require.Zero(t, p.tcpConnections.Load())
}

func TestHTTP3ConnectionRacingProxyAndFactory(t *testing.T) {
	for _, proxyType := range []string{"connect", "socks5"} {
		t.Run(proxyType, func(t *testing.T) {
			p := newRacingPeer(t, true, false, false)
			b := racingBuilder("firefox")
			if proxyType == "connect" {
				b.Proxy(g.String(newHTTPConnectProxy(t).URL))
			} else {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { listener.Close() })
				proxy := socks5.NewServer()
				proxy.Context = t.Context()
				proxy.ProxyListenPacket = func(context.Context, string, string) (net.PacketConn, error) {
					return net.ListenPacket("udp4", "127.0.0.1:0")
				}
				go proxy.Serve(listener)
				b.Proxy(g.String("socks5://" + listener.Addr().String()))
			}
			b.QUICSettings().HandshakeIdleTimeout(500 * time.Millisecond).Set()
			client := b.HTTP3Settings().ConnectionRacing(true).TCPFallbackDelay(0).Set().Build().Unwrap()
			defer client.Close()
			var factories atomic.Int32
			body := &racingBody{data: strings.NewReader("factory body")}
			response := client.Post(g.String(p.url)).StreamingBodyFactory(func() (io.ReadCloser, error) { factories.Add(1); return body, nil }).Do().Unwrap()
			require.Equal(t, 2, response.GetResponse().ProtoMajor)
			response.Body.String().Unwrap()
			require.EqualValues(t, 1, factories.Load())
			require.EqualValues(t, len("factory body"), body.bytes.Load())
			require.EqualValues(t, 1, p.tcpCalls.Load())
			require.Zero(t, p.quicCalls.Load())
		})
	}
}

func TestHTTP3ConnectionRacingAbandonedAttemptAndClose(t *testing.T) {
	p := newRacingPeer(t, true, false, true)
	b := racingBuilder("firefox")
	b.QUICSettings().HandshakeIdleTimeout(time.Second).Set()
	client := b.HTTP3Settings().ConnectionRacing(true).TCPFallbackDelay(0).Set().Build().Unwrap()
	ctx, cancel := context.WithCancel(t.Context())
	body := &racingBody{data: strings.NewReader("unread")}
	done := make(chan error, 1)
	go func() { done <- client.Post(g.String(p.url)).WithContext(ctx).StreamingBody(body).Do().Err() }()
	waitRacingSignal(t, p.udp.seen)
	waitRacingSignal(t, p.tcpHello)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.Zero(t, body.bytes.Load())
	require.EqualValues(t, 1, body.closes.Load())
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not stop pending preparation")
	}
	require.True(t, client.Get(g.String(p.url)).Do().IsErr())
	require.Zero(t, p.tcpCalls.Load())
	require.Zero(t, p.quicCalls.Load())
}

func TestHTTP3ConnectionRacingCertificateFailureDoesNotReadBody(t *testing.T) {
	p := newRacingPeer(t, true, true, false)
	client := racingBuilder("native").TLSConfig(&tls.Config{}).HTTP3Settings().ConnectionRacing(true).TCPFallbackDelay(0).Set().Build().Unwrap()
	defer client.Close()
	body := &racingBody{data: strings.NewReader("never send without verified TLS")}
	result := client.Post(g.String(p.url)).StreamingBody(body).Do()
	require.True(t, result.IsErr())
	require.ErrorContains(t, result.Err(), "preparation failed")
	require.Zero(t, body.bytes.Load())
	require.EqualValues(t, 1, body.closes.Load())
	require.Zero(t, p.tcpCalls.Load())
	require.Zero(t, p.quicCalls.Load())
}
