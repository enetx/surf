package surf_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/surf"
	"github.com/stretchr/testify/require"
)

func TestHTTP3CoalescingServerAuthorizationAndDNS(t *testing.T) {
	for _, tc := range []struct {
		name, options, advertised, target string
		ignoreIP, disabled, noOrigin      bool
		lookupTarget, success             bool
	}{
		{name: "same IP and certificate", target: "b.test", lookupTarget: true, success: true},
		{name: "ORIGIN skips DNS", advertised: "b.test", target: "b.test", success: true},
		{name: "NOIP explicit opt-in skips DNS", options: "ORIGNOIP", ignoreIP: true, target: "b.test", success: true},
		{name: "Chrome NOIP default remains off", options: "ORIGNOIP", target: "b.test"},
		{name: "unaligned NOIP is not an option", options: "xNOIPxxx", ignoreIP: true, target: "b.test"},
		{name: "invalid option vector", options: "NOIPx", ignoreIP: true, target: "b.test"},
		{name: "ORIGIN does not waive certificates", advertised: "bad.test", target: "bad.test"},
		{name: "NOIP does not waive certificates", options: "NOIP", ignoreIP: true, target: "bad.test"},
		{name: "ORIGIN handling can be disabled", advertised: "b.test", noOrigin: true, target: "b.test"},
		{name: "coalescing can be disabled", advertised: "b.test", disabled: true, target: "b.test", lookupTarget: true, success: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var origins func(string) []string
			if tc.advertised != "" {
				origins = func(port string) []string { return []string{"https://" + net.JoinHostPort(tc.advertised, port)} }
			}
			p := newCoalescingTestPeer(t, tc.options, origins, nil)
			hosts := map[string][4]byte{"a.test": {127, 0, 0, 1}}
			if tc.lookupTarget {
				hosts[tc.target] = [4]byte{127, 0, 0, 1}
			}
			d := newCoalescingDNS(t, hosts)
			learned := make(chan []string, 2)
			b := coalescingBuilder(p, d)
			h := b.HTTP3Settings().ConnectionCoalescing(!tc.disabled).OriginFrames(!tc.noOrigin).
				IgnoreIPMatching(tc.ignoreIP).OnOrigin(func(_ *quic.Conn, origins []string) { learned <- origins })
			client := h.Set().Build().Unwrap()
			t.Cleanup(func() { client.Close() })
			// A built transport retains its policy snapshot.
			h.IgnoreIPMatching(!tc.ignoreIP).ConnectionCoalescing(tc.disabled).OriginFrames(tc.noOrigin)
			_, err := coalescingGet(t, client, "a.test", p.port)
			if tc.options != "" && len(tc.options)%4 != 0 {
				require.Error(t, err, "QUICHE rejects a malformed connection-option vector during the handshake")
				return
			}
			require.NoError(t, err)
			first := coalescingObserved(t, p)
			if tc.advertised != "" && !tc.disabled && !tc.noOrigin {
				select {
				case <-learned:
				case <-time.After(5 * time.Second):
					t.Fatal("ORIGIN was not processed")
				}
			}
			_, err = coalescingGet(t, client, tc.target, p.port)
			if !tc.success {
				require.Error(t, err, "a non-authorized authority with NXDOMAIN must not use another origin's session")
				require.EqualValues(t, 1, p.accepted.Load())
				return
			}
			require.NoError(t, err)
			second := coalescingObserved(t, p)
			require.Equal(t, net.JoinHostPort(tc.target, p.port), second.authority)
			if tc.disabled {
				require.NotEqual(t, first.connection, second.connection)
			} else {
				require.Equal(t, first.connection, second.connection)
			}
			if !tc.lookupTarget {
				require.Zero(t, d.count(tc.target), "explicit server authorization must bypass address lookup")
			}
		})
	}
}

func TestHTTP3CoalescingAllMethodsRetainOrderedUserHeaders(t *testing.T) {
	p := newCoalescingTestPeer(t, "", nil, nil)
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "b.test": {127, 0, 0, 1}})
	client := coalescingBuilder(p, d).Build().Unwrap()
	defer client.Close()
	_, err := coalescingGet(t, client, "a.test", p.port)
	require.NoError(t, err)
	first := coalescingObserved(t, p)
	for _, tc := range []struct {
		method string
		new    func(g.String) *surf.Request
	}{
		{"GET", client.Get}, {"POST", client.Post}, {"PUT", client.Put},
		{"PATCH", client.Patch}, {"DELETE", client.Delete}, {"HEAD", client.Head},
		{"OPTIONS", client.Options}, {"TRACE", client.Trace},
	} {
		t.Run(tc.method, func(t *testing.T) {
			headers := g.NewMapOrd[g.String, g.String]()
			headers.Insert("X-Second", "two")
			headers.Insert("X-First", "one")
			request := tc.new(g.String("https://b.test:" + p.port + "/")).SetHeaders(headers)
			payload := ""
			if slices.Contains([]string{"POST", "PUT", "PATCH", "DELETE"}, tc.method) {
				payload = "ordered upload " + tc.method
				request.Body(payload)
			}
			response := request.Do().Unwrap()
			if tc.method != "HEAD" {
				response.Body.String().Unwrap()
			}
			observed := coalescingObserved(t, p)
			require.Equal(t, first.connection, observed.connection)
			require.Equal(t, tc.method, observed.method)
			require.Equal(t, payload, observed.body)
			var user []string
			for _, field := range observed.fields {
				if strings.HasPrefix(field.Name, "x-") {
					user = append(user, field.Name)
				}
			}
			require.Equal(t, []string{"x-second", "x-first"}, user)
		})
	}
	require.EqualValues(t, 1, p.accepted.Load())
}

func TestHTTP3CoalescingKeepsCustomTLSAndClientsIsolated(t *testing.T) {
	for _, mode := range []string{"insecure", "custom verifier", "client certificate", "separate clients"} {
		t.Run(mode, func(t *testing.T) {
			p := newCoalescingTestPeer(t, "", nil, nil)
			d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "b.test": {127, 0, 0, 1}})
			config := &tls.Config{RootCAs: p.roots}
			switch mode {
			case "insecure":
				config.InsecureSkipVerify = true
			case "custom verifier":
				config.VerifyConnection = func(tls.ConnectionState) error { return nil }
			case "client certificate":
				config.Certificates = []tls.Certificate{p.cert}
			}
			client := coalescingBuilder(p, d).TLSConfig(config).Build().Unwrap()
			defer client.Close()
			_, err := coalescingGet(t, client, "a.test", p.port)
			require.NoError(t, err)
			coalescingObserved(t, p)
			if mode == "separate clients" {
				other := coalescingBuilder(p, d).Build().Unwrap()
				defer other.Close()
				client = other
			}
			_, err = coalescingGet(t, client, "b.test", p.port)
			require.NoError(t, err)
			coalescingObserved(t, p)
			require.EqualValues(t, 2, p.accepted.Load())
		})
	}
}

type coalescingOneShot struct {
	io.Reader
	closed atomic.Int32
}

func (b *coalescingOneShot) Close() error { b.closed.Add(1); return nil }
func (b *coalescingOneShot) Read(p []byte) (int, error) {
	if b.closed.Load() != 0 {
		return 0, io.ErrClosedPipe
	}
	return b.Reader.Read(p)
}

func TestHTTP3CoalescingCacheMissDoesNotCloseOneShotUpload(t *testing.T) {
	p := newCoalescingTestPeer(t, "", nil, nil)
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}})
	client := coalescingBuilder(p, d).Build().Unwrap()
	defer client.Close()
	body := &coalescingOneShot{Reader: strings.NewReader("keep the caller's stream open on a cache miss")}
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://a.test:"+p.port, body)
	require.NoError(t, err)
	response, err := client.GetClient().Do(req)
	require.NoError(t, err)
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	require.Equal(t, 200, response.StatusCode)
	require.Equal(t, "keep the caller's stream open on a cache miss", coalescingObserved(t, p).body)
}

func TestHTTP3Coalescing421ReplaysOnceWithoutPoisoningOtherAuthorities(t *testing.T) {
	p := newCoalescingTestPeer(t, "", nil, func(r coalescingObservation) int {
		if strings.HasPrefix(r.authority, "b.test:") && r.connection == 1 {
			return 421
		}
		return 200
	})
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "b.test": {127, 0, 0, 1}, "c.test": {127, 0, 0, 1}})
	client := coalescingBuilder(p, d).Build().Unwrap()
	defer client.Close()
	_, err := coalescingGet(t, client, "a.test", p.port)
	require.NoError(t, err)
	coalescingObserved(t, p)
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://b.test:"+p.port, strings.NewReader("replay exactly this"))
	require.NoError(t, err)
	response, err := client.GetClient().Do(req)
	require.NoError(t, err)
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	require.Equal(t, 200, response.StatusCode)
	first, second := coalescingObserved(t, p), coalescingObserved(t, p)
	require.EqualValues(t, 1, first.connection)
	require.EqualValues(t, 2, second.connection)
	require.Equal(t, "replay exactly this", first.body)
	require.Equal(t, first.body, second.body)
	_, err = coalescingGet(t, client, "c.test", p.port)
	require.NoError(t, err)
	third := coalescingObserved(t, p)
	require.EqualValues(t, 1, third.connection, "421 must not permanently disable the original session")
}

func TestHTTP3Coalescing421DoesNotReplayOneShotUpload(t *testing.T) {
	p := newCoalescingTestPeer(t, "", nil, func(r coalescingObservation) int {
		if strings.HasPrefix(r.authority, "b.test:") {
			return 421
		}
		return 200
	})
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "b.test": {127, 0, 0, 1}})
	client := coalescingBuilder(p, d).Build().Unwrap()
	defer client.Close()
	_, err := coalescingGet(t, client, "a.test", p.port)
	require.NoError(t, err)
	coalescingObserved(t, p)
	body := &coalescingOneShot{Reader: strings.NewReader("one shot")}
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://b.test:"+p.port, body)
	require.NoError(t, err)
	require.Nil(t, req.GetBody)
	response, err := client.GetClient().Do(req)
	require.NoError(t, err)
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	require.Equal(t, 421, response.StatusCode)
	require.EqualValues(t, 1, p.accepted.Load())
	require.Equal(t, "one shot", coalescingObserved(t, p).body)
}

func TestHTTP3Coalescing421BrowserRetryUsesTCPAndIsTransactionLocal(t *testing.T) {
	p := newCoalescingTestPeer(t, "", func(port string) []string {
		return []string{"https://b.test:" + port, "https://c.test:" + port}
	}, func(r coalescingObservation) int {
		if strings.HasPrefix(r.authority, "b.test:") {
			return 421
		}
		return 200
	})
	tcp, err := net.Listen("tcp4", "127.0.0.1:"+p.port)
	require.NoError(t, err)
	requests := make(chan string, 4)
	server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{p.cert}, KeyLogWriter: p.keyLog}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("TCP retry body: %v", err)
		}
		requests <- r.Method + ":" + string(body)
		w.Write([]byte("tcp"))
	})}
	go server.ServeTLS(tcp, "", "")
	t.Cleanup(func() { server.Close(); tcp.Close() })
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}, "b.test": {127, 0, 0, 1}, "c.test": {127, 0, 0, 1}})
	learned := make(chan struct{}, 4)
	port, err := strconv.ParseUint(p.port, 10, 16)
	require.NoError(t, err)
	b := surf.NewClient().Builder().Impersonate().Chrome().Proxy("").DNS(g.String(d.address))
	b.HTTP3Settings().TCPFallbackDelay(time.Hour).OnOrigin(func(*quic.Conn, []string) { learned <- struct{}{} }).
		HTTPSRecordsLookup(func(context.Context, string) ([]surf.HTTPSRecord, error) {
			return []surf.HTTPSRecord{{Priority: 1, Target: "127.0.0.1", Port: uint16(port), ALPN: []string{"h3", "h2"}, TTL: time.Minute}}, nil
		}).Set()
	client := b.TLSConfig(&tls.Config{RootCAs: p.roots}).Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	response, err := coalescingGet(t, client, "a.test", p.port)
	require.NoError(t, err)
	require.Equal(t, 3, response.ProtoMajor)
	coalescingObserved(t, p)
	select {
	case <-learned:
	case <-time.After(5 * time.Second):
		t.Fatal("no ORIGIN frame")
	}
	for range 2 {
		response := client.Post(g.String("https://b.test:" + p.port)).Body("preserve this POST").Do().Unwrap()
		require.Equal(t, g.String("tcp"), response.Body.String().Unwrap())
		require.Equal(t, 2, response.GetResponse().ProtoMajor)
		require.Equal(t, "POST:preserve this POST", <-requests)
		require.EqualValues(t, 1, coalescingObserved(t, p).connection, "the next transaction may try the existing session again")
	}
	_, err = coalescingGet(t, client, "c.test", p.port)
	require.NoError(t, err)
	require.EqualValues(t, 1, coalescingObserved(t, p).connection)
	require.EqualValues(t, 1, p.accepted.Load())
}

func TestHTTP3CoalescingOriginLimitCountsDistinctValidEntries(t *testing.T) {
	p := newCoalescingTestPeer(t, "", func(port string) []string {
		return []string{
			"not an origin", "https://b.test:" + port + "/path", "http://unused.test",
			"https://b.test:" + port, "https://b.test:" + port,
			"https://c.test:" + port, "https://ignored.example:" + port,
		}
	}, nil)
	d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}})
	learned := make(chan []string, 2)
	b := coalescingBuilder(p, d)
	h := b.HTTP3Settings().OriginFrameLimit(3).OnOrigin(func(_ *quic.Conn, origins []string) { learned <- origins })
	client := h.Set().Build().Unwrap()
	defer client.Close()
	h.OriginFrameLimit(1) // Must not mutate the built policy.
	_, err := coalescingGet(t, client, "a.test", p.port)
	require.NoError(t, err)
	coalescingObserved(t, p)
	select {
	case origins := <-learned:
		require.Len(t, origins, 3)
	case <-time.After(5 * time.Second):
		t.Fatal("no learned origins")
	}
	for _, host := range []string{"b.test", "c.test"} {
		_, err = coalescingGet(t, client, host, p.port)
		require.NoError(t, err)
		require.EqualValues(t, 1, coalescingObserved(t, p).connection)
		require.Zero(t, d.count(host))
	}
	_, err = coalescingGet(t, client, "ignored.example", p.port)
	require.Error(t, err)
}

func TestHTTP3CoalescingOriginsAndNOIPHandlePortsSeparately(t *testing.T) {
	for _, mode := range []string{"ORIGIN exact port", "ORIGIN wrong port", "NOIP explicit"} {
		t.Run(mode, func(t *testing.T) {
			options := ""
			if mode == "NOIP explicit" {
				options = "NOIP"
			}
			p := newCoalescingTestPeer(t, options, func(port string) []string {
				if mode == "ORIGIN wrong port" {
					return []string{"https://b.test:" + port}
				}
				return []string{"https://b.test"}
			}, nil)
			d := newCoalescingDNS(t, map[string][4]byte{"a.test": {127, 0, 0, 1}})
			learned := make(chan struct{}, 2)
			b := coalescingBuilder(p, d)
			b.HTTP3Settings().IgnoreIPMatching(mode == "NOIP explicit").OnOrigin(func(*quic.Conn, []string) { learned <- struct{}{} }).Set()
			client := b.Build().Unwrap()
			defer client.Close()
			_, err := coalescingGet(t, client, "a.test", p.port)
			require.NoError(t, err)
			coalescingObserved(t, p)
			select {
			case <-learned:
			case <-time.After(5 * time.Second):
				t.Fatal("no origin")
			}
			_, err = coalescingGet(t, client, "b.test", "443")
			if mode == "ORIGIN wrong port" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, "b.test:443", coalescingObserved(t, p).authority)
				require.EqualValues(t, 1, p.accepted.Load())
				require.Zero(t, d.count("b.test"))
			}
		})
	}
}
