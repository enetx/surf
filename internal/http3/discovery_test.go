package h3transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/enetx/http"
	"github.com/stretchr/testify/require"
)

func TestAltSvcAuthenticationParsingAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		header   string
		age      string
		accepted bool
	}{
		{`h3=":8443"; ma=60`, "", true},
		{`h2=":443", h3="other.example:443"; ma="60"; persist=1`, "", true},
		{`h3=":8443"; ma=60`, "60", false},
		{`h3=":8443"; ma=-1`, "", false},
		{`h3=":0"`, "", false},
		{`h3="user@evil.example:443"`, "", false},
		{`h3-29=":443"`, "", false},
		{`h3=":8443"; unknown="a,b;c"; ma=60`, "", true},
	} {
		d := newAlternativeDiscovery(nil, nil, false)
		now := time.Now()
		d.now = func() time.Time { return now }
		response := &http.Response{Header: http.Header{"Alt-Svc": {tc.header}, "Age": {tc.age}}}
		d.observe("origin.example:443", response)
		_, ok := d.get("origin.example:443")
		require.False(t, ok, "unauthenticated advertisement")
		response.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{new(x509.Certificate)}}}
		d.observe("origin.example:443", response)
		_, ok = d.get("origin.example:443")
		require.Equal(t, tc.accepted, ok, tc.header)
		_, ok = d.get("different.example:443")
		require.False(t, ok)
		now = now.Add(24 * time.Hour)
		_, ok = d.get("origin.example:443")
		require.False(t, ok)
	}
}

func TestAlternativeFailureCancellationExpiryAndRefresh(t *testing.T) {
	for _, discard := range []bool{false, true} {
		now := time.Now()
		d := newAlternativeDiscovery(nil, func(uint32) time.Duration { return time.Second }, discard)
		d.now = func() time.Time { return now }
		route := alternativeRoute{
			origin:     "origin:443",
			address:    "alt:8443",
			expires:    now.Add(time.Hour),
			fromAltSvc: true,
		}
		d.put(route)
		d.result(route, context.Canceled)
		_, ok := d.get(route.origin)
		require.True(t, ok)
		d.result(route, errors.New("handshake failed"))
		_, ok = d.get(route.origin)
		require.False(t, ok)
		d.put(route) // A refreshed advertisement must not erase active brokenness.
		_, ok = d.get(route.origin)
		require.False(t, ok)
		if discard {
			d.result(route, errors.New("handshake failed"))
		}
		now = now.Add(2 * time.Second)
		_, ok = d.get(route.origin)
		require.Equal(t, !discard, ok)
		d.put(route)
		d.result(route, nil)
		_, ok = d.get(route.origin)
		require.True(t, ok)
		require.Empty(t, d.failures)
	}
}

func TestHTTPSBindingSelectionAndCache(t *testing.T) {
	var queries []string
	d := newAlternativeDiscovery(func(_ context.Context, name string) ([]HTTPSRecord, error) {
		queries = append(queries, name)
		return []HTTPSRecord{
			{
				Priority:  1,
				Target:    "unsupported.example",
				ALPN:      []string{"h3"},
				TTL:       time.Minute,
				Mandatory: []uint16{65000},
			},
			{Priority: 3, Target: "last.example", ALPN: []string{"h3"}, TTL: time.Minute},
			{
				Priority: 2,
				Target:   "selected.example.",
				Port:     9443,
				ALPN:     []string{"h2", "h3"},
				TTL:      time.Minute,
				ECH:      []byte{0, 1},
			},
		}, nil
	}, nil, false)
	route, ok := d.resolve(t.Context(), "origin.example:8443")
	require.True(t, ok)
	require.Equal(t, "selected.example:9443", route.address)
	require.Equal(t, []byte{0, 1}, route.ech)
	require.Equal(t, []string{"_8443._https.origin.example"}, queries)
	_, ok = d.resolve(t.Context(), "origin.example:8443")
	require.True(t, ok)
	require.Len(t, queries, 1)
}

func TestHTTPSRecordStrictWireValidation(t *testing.T) {
	// ServiceMode, root target, mandatory=alpn+port, h3 ALPN, port 8443.
	valid := []byte{0, 1, 0, 0, 0, 0, 4, 0, 1, 0, 3, 0, 1, 0, 3, 2, 'h', '3', 0, 3, 0, 2, 0x20, 0xfb}
	r, err := parseHTTPSRecord(valid, time.Minute)
	require.NoError(t, err)
	require.EqualValues(t, 8443, r.Port)
	require.Equal(t, []string{"h3"}, r.ALPN)
	for _, invalid := range [][]byte{
		{0, 1, 0xc0, 0},                                         // Compressed TargetName is forbidden.
		{0, 1, 0, 0, 1, 0, 1, 0},                                // Empty ALPN item.
		{0, 1, 0, 0, 3, 0, 2, 0, 0},                             // Zero port.
		{0, 1, 0, 0, 2, 0, 0},                                   // no-default-alpn requires explicit ALPN.
		{0, 1, 0, 0, 0, 0, 2, 0, 3},                             // Missing mandatory port.
		append(append([]byte(nil), valid...), 0, 3, 0, 2, 1, 1), // Duplicate key.
	} {
		_, err := parseHTTPSRecord(invalid, time.Minute)
		require.Error(t, err, invalid)
	}
	// Every strict prefix is truncated or missing one of the mandatory fields.
	for n := 0; n < len(valid); n++ {
		if n == 3 {
			continue
		} // A bare ServiceMode record is well formed.
		_, err := parseHTTPSRecord(valid[:n], time.Minute)
		require.Error(t, err, "prefix %d", n)
	}
	unknown := append(append([]byte(nil), valid...), 0xfd, 0xe8, 0, 2, 1, 2)
	_, err = parseHTTPSRecord(unknown, time.Minute)
	require.NoError(t, err)
}

func TestHTTPSDiscoverySharedLookupSurvivesOneCanceledWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		d := newAlternativeDiscovery(func(ctx context.Context, _ string) ([]HTTPSRecord, error) {
			calls.Add(1)
			close(started)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
				return []HTTPSRecord{{Priority: 1, Target: "alt.example", ALPN: []string{"h3"}, TTL: time.Minute}}, nil
			}
		}, nil, false)
		defer d.close()
		ctx, cancel := context.WithCancel(context.Background())
		first, second := make(chan bool, 1), make(chan bool, 1)
		go func() { _, ok := d.resolve(ctx, "origin.example:443"); first <- ok }()
		<-started
		go func() { _, ok := d.resolve(context.Background(), "origin.example:443"); second <- ok }()
		synctest.Wait()
		d.mu.Lock()
		require.Equal(t, 2, d.dnsFlights["origin.example:443"].waiters)
		d.mu.Unlock()
		cancel()
		require.False(t, <-first)
		close(release)
		require.True(t, <-second)
		require.EqualValues(t, 1, calls.Load())
	})
}

func TestHTTPSDiscoveryCloseCancelsLookup(t *testing.T) {
	started := make(chan struct{})
	d := newAlternativeDiscovery(func(ctx context.Context, _ string) ([]HTTPSRecord, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}, nil, false)
	done := make(chan bool, 1)
	go func() { _, ok := d.resolve(t.Context(), "origin.example:443"); done <- ok }()
	<-started
	d.close()
	select {
	case ok := <-done:
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("discovery survived transport close")
	}
}

func TestHTTPSDiscoveryLastCanceledWaiterAllowsFreshLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, stopped := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		d := newAlternativeDiscovery(func(ctx context.Context, _ string) ([]HTTPSRecord, error) {
			if calls.Add(1) == 1 {
				close(started)
				<-ctx.Done()
				close(stopped)
				return nil, context.Cause(ctx)
			}
			return []HTTPSRecord{{Priority: 1, ALPN: []string{"h3"}, TTL: time.Minute, ECH: []byte{1, 2}}}, nil
		}, nil, false)
		defer d.close()
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan bool, 1)
		go func() { _, ok := d.resolve(ctx, "origin.example:443"); done <- ok }()
		<-started
		cancel()
		require.False(t, <-done)
		<-stopped
		route, ok := d.resolve(t.Context(), "origin.example:443")
		require.True(t, ok)
		require.Equal(t, []byte{1, 2}, route.ech)
		require.EqualValues(t, 2, calls.Load(), "cancellation must not suppress the next lookup")
	})
}

func TestHTTPSBindingLifetimeAndECHSurviveBackoff(t *testing.T) {
	now := time.Now()
	failLookup := false
	d := newAlternativeDiscovery(func(context.Context, string) ([]HTTPSRecord, error) {
		if failLookup {
			return nil, errors.New("DNS unavailable")
		}
		return []HTTPSRecord{
			{Priority: 1, Target: "alt.example", ALPN: []string{"h3"}, TTL: 5 * time.Second, ECH: []byte{1, 2, 3}},
		}, nil
	}, func(uint32) time.Duration { return time.Second }, true)
	d.now = func() time.Time { return now }
	origin := "origin.example:443"
	route, ok, _ := d.resolveUnshared(t.Context(), origin)
	require.True(t, ok)
	d.result(route, errors.New("QUIC blocked"))
	_, ok = d.get(origin)
	require.False(t, ok)
	binding, ok := d.binding(origin)
	require.True(t, ok)
	require.Equal(t, []byte{1, 2, 3}, binding.ech)
	require.True(t, binding.tcp, "default ALPN permits the TCP transport")
	now = now.Add(6 * time.Second)
	require.True(t, d.needsDNSRefresh(origin), "positive DNS TTL is not extended by a one-minute miss throttle")
	failLookup = true
	_, ok, _ = d.resolveUnshared(t.Context(), origin)
	require.False(t, ok)
	require.True(t, d.expiredECH(origin), "failed refresh must fail closed instead of forgetting ECH")
	now = now.Add(time.Minute)
	failLookup = false
	_, ok, _ = d.resolveUnshared(t.Context(), origin)
	require.True(t, ok)
	require.False(t, d.expiredECH(origin))
}

func TestHTTPSNoDefaultALPNControlsTransportNotOfferedProtocols(t *testing.T) {
	for _, tc := range []struct {
		alpn               []string
		noDefault, h3, tcp bool
	}{
		{[]string{"h3"}, false, true, true},
		{[]string{"h3"}, true, true, false},
		{[]string{"h2"}, true, false, true},
		{[]string{"h3", "http/1.1"}, true, true, true},
		{[]string{"unknown"}, true, false, false},
	} {
		h3, tcp := bindingTransports(&HTTPSRecord{ALPN: tc.alpn, NoDefaultALPN: tc.noDefault})
		require.Equal(t, tc.h3, h3)
		require.Equal(t, tc.tcp, tcp)
	}
}
