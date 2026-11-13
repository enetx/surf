package surf_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
	h3transport "github.com/enetx/surf/internal/http3"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

type requiredHTTP1Peer struct {
	url               string
	roots             *x509.CertPool
	mu                sync.Mutex
	hellos            [][]string
	conns             map[net.Conn]bool
	workers           sync.WaitGroup
	h1                chan profileWireCapture
	h2                chan profileWireCapture
	drained           chan struct{}
	triggered         atomic.Bool
	clientGoAway      atomic.Int32
	goaway            bool
	inactive          bool
	code              http2.ErrCode
	batch             int
	responseHeaders   http.Header // Protected by mu; copied for each HTTP/1 connection.
	statusBeforeError int         // Protected by mu; optional response HEADERS before the error.
}

func newRequiredHTTP1Peer(t *testing.T, goaway, inactive bool, code http2.ErrCode, batch int, echKeys ...tls.EncryptedClientHelloKey) *requiredHTTP1Peer {
	t.Helper()
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert.Close()
	p := &requiredHTTP1Peer{
		goaway: goaway, inactive: inactive, code: code, batch: batch,
		roots: x509.NewCertPool(), conns: make(map[net.Conn]bool),
		h1: make(chan profileWireCapture, 32), h2: make(chan profileWireCapture, 32),
		drained:         make(chan struct{}, 32),
		responseHeaders: http.Header{"Content-Length": {"2"}},
	}
	p.roots.AddCert(cert.Certificate())
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: cert.TLS.Certificates, EncryptedClientHelloKeys: echKeys, NextProtos: []string{"h2", "http/1.1"}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		p.mu.Lock()
		p.hellos = append(p.hellos, slices.Clone(hello.SupportedProtos))
		p.mu.Unlock()
		return nil, nil
	}})
	require.NoError(t, err)
	p.url = "https://" + listener.Addr().String()
	p.workers.Add(1)
	go func() {
		defer p.workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns[conn] = true
			p.mu.Unlock()
			p.workers.Add(1)
			go func() {
				defer p.workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				secure := conn.(*tls.Conn)
				if secure.Handshake() != nil {
					return
				}
				if secure.ConnectionState().NegotiatedProtocol == "h2" {
					p.serveHTTP2(conn)
				} else {
					p.mu.Lock()
					headers := p.responseHeaders.Clone()
					p.mu.Unlock()
					_ = profileWireHTTP1(t, conn, headers, p.h1)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		p.mu.Lock()
		for conn := range p.conns {
			conn.Close()
		}
		p.mu.Unlock()
		p.workers.Wait()
	})
	return p
}

func (p *requiredHTTP1Peer) serveHTTP2(conn net.Conn) {
	defer func() { p.drained <- struct{}{} }()
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(1<<20, nil)
	if fr.WriteSettings() != nil {
		return
	}
	if p.batch == 0 {
		p.triggered.Store(true)
		if fr.WriteGoAway(0, p.code, nil) != nil {
			return
		}
	}
	streams := make(map[uint32]*profileWireCapture)
	var pending []uint32
	complete := func(id uint32) bool {
		capture := streams[id]
		delete(streams, id)
		p.h2 <- *capture
		if !p.triggered.Load() {
			pending = append(pending, id)
			if len(pending) < p.batch {
				return true
			}
			if p.triggered.CompareAndSwap(false, true) {
				p.mu.Lock()
				status := p.statusBeforeError
				p.mu.Unlock()
				if status != 0 {
					var block bytes.Buffer
					enc := hpack.NewEncoder(&block)
					if enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)}) != nil {
						return false
					}
					if status >= 200 {
						if enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "2"}) != nil {
							return false
						}
					}
					if fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndHeaders: true, BlockFragment: block.Bytes()}) != nil {
						return false
					}
				}
				if p.goaway {
					return fr.WriteGoAway(id, p.code, nil) == nil
				}
				target := pending[0]
				if p.inactive {
					target += 200
				}
				if fr.WriteRSTStream(target, p.code) != nil {
					return false
				}
				if !p.inactive {
					return true
				}
			}
		}
		return fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndHeaders: true, EndStream: true, BlockFragment: []byte{0x88}}) == nil
	}
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() && fr.WriteSettingsAck() != nil {
				return
			}
		case *http2.MetaHeadersFrame:
			capture := &profileWireCapture{}
			for _, h := range f.Fields {
				capture.fields = append(capture.fields, [2]string{h.Name, h.Value})
				switch h.Name {
				case ":method":
					capture.method = h.Value
				case ":path":
					capture.path = h.Value
				}
			}
			streams[f.StreamID] = capture
			if f.StreamEnded() && !complete(f.StreamID) {
				return
			}
		case *http2.DataFrame:
			if capture := streams[f.StreamID]; capture != nil {
				capture.body += string(f.Data())
				if f.StreamEnded() && !complete(f.StreamID) {
					return
				}
			}
		case *http2.GoAwayFrame:
			p.clientGoAway.Add(1)
		}
	}
}

func requiredHTTP1Builder(p *requiredHTTP1Peer, firefox bool) *surf.Builder {
	b := surf.NewClient().Builder().Proxy("").TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second)
	if firefox {
		return b.Impersonate().Firefox()
	}
	return b.Impersonate().Chrome()
}

func requiredHTTP1Get(t *testing.T, c *surf.Client, address string, major int) {
	t.Helper()
	result := c.Get(g.String(address)).Do()
	require.NoError(t, result.Err())
	response := result.Unwrap()
	require.Equal(t, major, response.GetResponse().ProtoMajor)
	response.Body.String().Unwrap()
}

func TestHTTP1RequirementIsRememberedOnlyForChrome(t *testing.T) {
	for _, scenario := range []struct{ firefox, goaway bool }{{false, false}, {false, true}, {true, false}} {
		firefox, goaway := scenario.firefox, scenario.goaway
		t.Run(fmt.Sprintf("firefox=%v/goaway=%v", firefox, goaway), func(t *testing.T) {
			p := newRequiredHTTP1Peer(t, goaway, false, http2.ErrCodeHTTP11Required, 1)
			c := requiredHTTP1Builder(p, firefox).Build().Unwrap()
			defer c.Close()
			requiredHTTP1Get(t, c, p.url, 1)
			if !firefox {
				select {
				case <-p.drained:
				case <-time.After(5 * time.Second):
					t.Fatal("rejected H2 session remained open")
				}
			}
			want := 1
			if firefox {
				want = 2
			}
			requiredHTTP1Get(t, c, p.url, want)
			c.CloseIdleConnections()
			req, _ := http.NewRequest(http.MethodGet, p.url, nil)
			tcp := c.GetTransport().(*h3transport.Transport).Fallback
			preconnect := tcp.(interface{ Preconnect(*http.Request) error })
			require.NoError(t, preconnect.Preconnect(req))
			requiredHTTP1Get(t, c, p.url, want)
			p.mu.Lock()
			hellos := slices.Clone(p.hellos)
			p.mu.Unlock()
			require.True(t, slices.Contains(hellos[0], "h2"))
			for _, hello := range hellos[1:] {
				if firefox {
					continue
				}
				require.Equal(t, []string{"http/1.1"}, hello)
			}
			require.Zero(t, p.clientGoAway.Load())
		})
	}
}

func TestHTTP1RequirementTerminatesAllPendingStreams(t *testing.T) {
	for _, goaway := range []bool{false, true} {
		t.Run(fmt.Sprint(goaway), func(t *testing.T) {
			p := newRequiredHTTP1Peer(t, goaway, false, http2.ErrCodeHTTP11Required, 2)
			c := requiredHTTP1Builder(p, false).Build().Unwrap()
			defer c.Close()
			errors := make(chan error, 2)
			for range 2 {
				go func() {
					result := c.Get(g.String(p.url)).Do()
					if result.IsErr() {
						errors <- result.Err()
						return
					}
					response := result.Unwrap()
					if response.GetResponse().ProtoMajor != 1 {
						errors <- fmt.Errorf("protocol=%s", response.Proto)
						return
					}
					body := response.Body.String()
					errors <- body.Err()
				}()
			}
			for range 2 {
				require.NoError(t, <-errors)
			}
			require.Len(t, p.h2, 2)
			require.Len(t, p.h1, 2)
			require.Zero(t, p.clientGoAway.Load())
		})
	}
}

func TestHTTP1RequirementLRUAndOriginIsolation(t *testing.T) {
	peers := []*requiredHTTP1Peer{newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1), newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1), newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1)}
	// Each httptest peer uses the same standard test certificate.
	roots := peers[0].roots
	b := requiredHTTP1Builder(peers[0], false).TLSConfig(&tls.Config{RootCAs: roots})
	c := b.HTTP2Settings().HTTP1RequiredCache(2).Set().Build().Unwrap()
	defer c.Close()
	for _, index := range []int{0, 1, 0, 2} {
		requiredHTTP1Get(t, c, peers[index].url, 1)
	}
	c.CloseIdleConnections()
	requiredHTTP1Get(t, c, peers[0].url, 1)
	requiredHTTP1Get(t, c, peers[1].url, 2)
	independent := requiredHTTP1Builder(peers[0], false).Build().Unwrap()
	defer independent.Close()
	requiredHTTP1Get(t, independent, peers[0].url, 2)
}

func TestHTTP1RequirementSharesOriginStateAcrossProxyRoutes(t *testing.T) {
	p := newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1)
	proxy := newHTTPConnectProxy(t)
	proxyURL, _ := url.Parse(proxy.URL)
	var direct atomic.Bool
	b := requiredHTTP1Builder(p, false).With(func(c *surf.Client) error {
		c.GetTransport().(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) {
			if direct.Load() {
				return nil, nil
			}
			return proxyURL, nil
		}
		return nil
	}, 1)
	c := b.Build().Unwrap()
	defer c.Close()
	requiredHTTP1Get(t, c, p.url, 1)
	direct.Store(true)
	requiredHTTP1Get(t, c, p.url, 1)
	p.mu.Lock()
	hellos := slices.Clone(p.hellos)
	p.mu.Unlock()
	require.Equal(t, []string{"http/1.1"}, hellos[len(hellos)-1])
}

func TestHTTP1RequirementIgnoresUnrelatedAndInactiveErrors(t *testing.T) {
	for _, inactive := range []bool{false, true} {
		t.Run(fmt.Sprint(inactive), func(t *testing.T) {
			code := http2.ErrCodeCancel
			if inactive {
				code = http2.ErrCodeHTTP11Required
			}
			p := newRequiredHTTP1Peer(t, false, inactive, code, 1)
			c := requiredHTTP1Builder(p, false).Build().Unwrap()
			defer c.Close()
			first := c.Get(g.String(p.url)).Do()
			if inactive {
				require.False(t, first.IsErr())
				first.Unwrap().Body.String().Unwrap()
			} else {
				require.True(t, first.IsErr())
			}
			requiredHTTP1Get(t, c, p.url, 2)
			require.Empty(t, p.h1)
		})
	}
}

func TestHTTP1RequirementPreservesOrderedHeadersAndReplayableBodies(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			p := newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1)
			baseline := requiredHTTP1Builder(p, false).ForceHTTP1().Build().Unwrap()
			defer baseline.Close()
			req, _, body := profileOrderRequest(t, baseline, p.url, method, nil)
			response := req.Do().Unwrap()
			if method != http.MethodHead {
				response.Body.String().Unwrap()
			} else {
				response.GetResponse().Body.Close()
			}
			want := <-p.h1
			c := requiredHTTP1Builder(p, false).Build().Unwrap()
			defer c.Close()
			req, _, _ = profileOrderRequest(t, c, p.url, method, nil)
			response = req.Do().Unwrap()
			require.Equal(t, 1, response.GetResponse().ProtoMajor)
			if method != http.MethodHead {
				response.Body.String().Unwrap()
			} else {
				response.GetResponse().Body.Close()
			}
			got := <-p.h1
			require.Equal(t, want.fields, got.fields)
			require.Equal(t, body, got.body)
		})
	}
}

func TestHTTP1RequirementKeepsHTTP3Available(t *testing.T) {
	p := newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1)
	quic := newDiscoveryPeer(t, nil)
	p.mu.Lock()
	p.responseHeaders.Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=60`, quic.port))
	p.mu.Unlock()
	// Disable racing only to make transport selection deterministic. The
	// remembered requirement belongs to TCP/H2 and must not suppress valid H3.
	c := requiredHTTP1Builder(p, false).HTTP3Settings().ConnectionRacing(false).TCPFallbackDelay(time.Hour).Set().Build().Unwrap()
	defer c.Close()
	requiredHTTP1Get(t, c, p.url, 1)
	requiredHTTP1Get(t, c, p.url, 3)
	require.EqualValues(t, 1, quic.h3Count.Load())
}

func TestHTTP1RequirementCacheOverrideAndFrozenBuilder(t *testing.T) {
	for _, disable := range []bool{false, true} {
		t.Run(fmt.Sprint(disable), func(t *testing.T) {
			p := newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1)
			b := requiredHTTP1Builder(p, false)
			if disable {
				b.HTTP2Settings().HTTP1RequiredCache(0).Set()
			}
			c := b.Build().Unwrap()
			defer c.Close()
			// Later edits cannot change the built transport's selected policy.
			if disable {
				b.HTTP2Settings().HTTP1RequiredCache(100)
			} else {
				b.HTTP2Settings().HTTP1RequiredCache(0)
			}
			requiredHTTP1Get(t, c, p.url, 1)
			major := 1
			if disable {
				major = 2
			}
			requiredHTTP1Get(t, c, p.url, major)
		})
	}
	for _, size := range []int{-1, 1<<20 + 1} {
		result := surf.NewClient().Builder().JA().Chrome158().HTTP2Settings().HTTP1RequiredCache(size).Set().Build()
		require.True(t, result.IsErr())
	}
}

func TestHTTP1RequirementRemembersEvenIfBodyCannotBeReplayed(t *testing.T) {
	p := newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1)
	c := requiredHTTP1Builder(p, false).Build().Unwrap()
	defer c.Close()
	req, err := http.NewRequest(http.MethodPost, p.url, io.NopCloser(strings.NewReader("one-shot")))
	require.NoError(t, err)
	require.Nil(t, req.GetBody)
	response, err := c.GetClient().Do(req)
	if response != nil {
		response.Body.Close()
	}
	require.ErrorContains(t, err, "GetBody is nil")
	require.Equal(t, "one-shot", (<-p.h2).body)
	require.Empty(t, p.h1, "a consumed one-shot body must not be replayed")
	requiredHTTP1Get(t, c, p.url, 1)
}

func TestHTTP1RequirementUsesDestinationInsteadOfHostOverride(t *testing.T) {
	p := newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1)
	c := requiredHTTP1Builder(p, false).Build().Unwrap()
	defer c.Close()
	req := c.Get(g.String(p.url))
	req.GetRequest().Host = "unrelated.invalid"
	response := req.Do().Unwrap()
	require.Equal(t, 1, response.GetResponse().ProtoMajor)
	response.Body.String().Unwrap()
	c.CloseIdleConnections()
	requiredHTTP1Get(t, c, p.url, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	require.Equal(t, []string{"http/1.1"}, p.hellos[len(p.hellos)-1])
}

func TestHTTP1RequirementJAChromeDefault(t *testing.T) {
	p := newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1)
	c := surf.NewClient().Builder().Proxy("").TLSConfig(&tls.Config{RootCAs: p.roots}).JA().Chrome158().Timeout(5 * time.Second).Build().Unwrap()
	defer c.Close()
	requiredHTTP1Get(t, c, p.url, 1)
	requiredHTTP1Get(t, c, p.url, 1)
}

func TestHTTP1RequirementFromIdlePreconnectGOAWAY(t *testing.T) {
	p := newRequiredHTTP1Peer(t, true, false, http2.ErrCodeHTTP11Required, 0)
	c := requiredHTTP1Builder(p, false).Build().Unwrap()
	defer c.Close()
	tcp := c.GetTransport().(*h3transport.Transport).Fallback
	req, err := http.NewRequest(http.MethodGet, p.url, nil)
	require.NoError(t, err)
	err = tcp.(interface{ Preconnect(*http.Request) error }).Preconnect(req)
	if err != nil {
		require.ErrorContains(t, err, "HTTP_1_1_REQUIRED")
	}
	select {
	case <-p.drained:
	case <-time.After(5 * time.Second):
		t.Fatal("idle HTTP/2 session was not closed")
	}
	requiredHTTP1Get(t, c, p.url, 1)
	require.Empty(t, p.h2, "Preconnect must not send an HTTP request")
	require.Zero(t, p.clientGoAway.Load())
}

func TestHTTP1RequirementAfterResponseHeaders(t *testing.T) {
	for _, status := range []int{http.StatusEarlyHints, http.StatusOK} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			p := newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1)
			p.mu.Lock()
			p.statusBeforeError = status
			p.mu.Unlock()
			c := requiredHTTP1Builder(p, false).Build().Unwrap()
			defer c.Close()
			result := c.Get(g.String(p.url)).Do()
			require.NoError(t, result.Err())
			response := result.Unwrap()
			if status == http.StatusEarlyHints {
				// Chromium handles explicit HTTP_1_1_REQUIRED while still reading
				// response headers, including after an informational response.
				require.Equal(t, 1, response.GetResponse().ProtoMajor)
				response.Body.String().Unwrap()
				require.Len(t, p.h1, 1)
			} else {
				require.Equal(t, 2, response.GetResponse().ProtoMajor)
				_, err := io.ReadAll(response.GetResponse().Body)
				response.GetResponse().Body.Close()
				require.ErrorContains(t, err, "HTTP_1_1_REQUIRED")
				require.Empty(t, p.h1, "final response headers must not cause request replay")
			}
			requiredHTTP1Get(t, c, p.url, 1)
		})
	}
}

func TestHTTP1RequirementRetainsVerifiedECH(t *testing.T) {
	configs, key := testECHConfig(t)
	p := newRequiredHTTP1Peer(t, false, false, http2.ErrCodeHTTP11Required, 1, key)
	var checked atomic.Int32
	config := &tls.Config{RootCAs: p.roots, ServerName: "example.com", EncryptedClientHelloConfigList: configs,
		VerifyConnection: func(state tls.ConnectionState) error {
			n := checked.Add(1)
			if !state.ECHAccepted || len(state.VerifiedChains) == 0 {
				return fmt.Errorf("handshake %d did not establish verified ECH", n)
			}
			if n > 1 && state.NegotiatedProtocol != "http/1.1" {
				return fmt.Errorf("cached ECH handshake negotiated %q", state.NegotiatedProtocol)
			}
			return nil
		},
	}
	c := requiredHTTP1Builder(p, false).TLSConfig(config).Session().Build().Unwrap()
	defer c.Close()
	requiredHTTP1Get(t, c, p.url, 1)
	c.CloseIdleConnections()
	requiredHTTP1Get(t, c, p.url, 1)
	require.EqualValues(t, 3, checked.Load(), "initial H2 plus two fresh HTTP/1 handshakes")
}
