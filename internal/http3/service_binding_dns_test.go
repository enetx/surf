package h3transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestTCPBindingUsesOnlyMatchingResolvedAddresses(t *testing.T) {
	for _, tc := range []struct {
		name, network, target, want string
		lookupErr                   error
		hints                       []netip.Addr
	}{
		{name: "origin", network: "tcp4", want: "127.0.0.1:443"},
		{name: "ipv6", network: "tcp6", want: "[fe80::1%zone]:443"},
		{name: "alias", network: "tcp", target: "alias.test:8443", want: "alias.test:8443"},
		{name: "hint-after-error", network: "tcp4", lookupErr: &net.DNSError{Err: "missing", IsNotFound: true}, hints: []netip.Addr{netip.MustParseAddr("127.0.0.2")}, want: "127.0.0.2:443"},
		{name: "dns-error", network: "tcp4", lookupErr: &net.DNSError{Err: "missing", IsNotFound: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var called []string
			dial := tcpBindingDial(func(_ context.Context, network, address string) (net.Conn, error) {
				if network != tc.network {
					t.Error("network was changed")
				}
				called = append(called, address)
				a, b := net.Pipe()
				b.Close()
				return a, nil
			}, -1, true)
			resolved := &resolvedAddresses{host: "origin.test", err: tc.lookupErr,
				ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("fe80::1"), Zone: "zone"}}}
			if tc.lookupErr != nil {
				resolved.ips = nil
			}
			route := alternativeRoute{origin: "origin.test:443", tcpAddress: tc.target, resolved: resolved, hints: tc.hints}
			ctx := context.WithValue(t.Context(), alternativeRouteKey{}, route)
			conn, err := dial(ctx, tc.network, route.origin)
			if tc.want == "" {
				if !errors.Is(err, tc.lookupErr) || len(called) != 0 {
					t.Fatalf("discarded resolver error: %v %v", err, called)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if len(called) != 1 || called[0] != tc.want {
				t.Fatalf("dialed %v, want %s", called, tc.want)
			}
		})
	}
}
