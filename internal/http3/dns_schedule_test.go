package h3transport

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/http"
)

func receiveDNS[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("DNS task did not complete")
		var zero T
		return zero
	}
}

func TestDNSSupplementalWaitStartsAfterAddresses(t *testing.T) {
	addressStarted, httpsStarted := make(chan struct{}), make(chan struct{})
	releaseAddress, httpsCanceled := make(chan struct{}), make(chan struct{})
	waitCalled := make(chan time.Duration, 1)
	d := newAlternativeDiscovery(func(ctx context.Context, _ string) ([]HTTPSRecord, error) {
		close(httpsStarted)
		<-ctx.Done()
		close(httpsCanceled)
		return nil, context.Cause(ctx)
	}, nil, false)
	d.addressLookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		close(addressStarted)
		select {
		case <-releaseAddress:
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
	d.httpsWait = func(elapsed time.Duration) time.Duration { waitCalled <- elapsed; return time.Millisecond }
	type result struct {
		addresses *resolvedAddresses
		err       error
	}
	done := make(chan result, 1)
	go func() {
		_, addresses, err := d.resolveDNS(t.Context(), "origin.test", "origin.test")
		done <- result{addresses, err}
	}()
	receiveDNS(t, addressStarted)
	receiveDNS(t, httpsStarted)
	select {
	case <-waitCalled:
		t.Fatal("timer started before addresses completed")
	default:
	}
	close(releaseAddress)
	if receiveDNS(t, waitCalled) < 0 {
		t.Fatal("invalid lookup duration")
	}
	r := receiveDNS(t, done)
	if r.err == nil || r.addresses == nil || len(r.addresses.ips) != 1 {
		t.Fatal("HTTPS timeout discarded address result")
	}
	receiveDNS(t, httpsCanceled)
}

func TestDNSWaitsForBothResultsAndCancelsWorkers(t *testing.T) {
	for _, mode := range []string{"https-first", "addresses-first", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan string, 2)
			addressRelease, httpsRelease := make(chan struct{}), make(chan struct{})
			stopped := make(chan string, 2)
			d := newAlternativeDiscovery(func(ctx context.Context, _ string) ([]HTTPSRecord, error) {
				started <- "https"
				defer func() { stopped <- "https" }()
				select {
				case <-httpsRelease:
					return []HTTPSRecord{{Priority: 1, ECH: []byte{1}}}, nil
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				}
			}, nil, false)
			d.addressLookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
				started <- "addresses"
				defer func() { stopped <- "addresses" }()
				select {
				case <-addressRelease:
					return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				records, addresses, err := d.resolveDNS(ctx, "origin.test", "origin.test")
				if err == nil && (len(records) != 1 || addresses == nil || len(addresses.ips) != 1) {
					err = errors.New("lost DNS result")
				}
				done <- err
			}()
			receiveDNS(t, started)
			receiveDNS(t, started)
			if mode == "cancel" {
				cancel()
			} else {
				if mode == "https-first" {
					close(httpsRelease)
				} else {
					close(addressRelease)
				}
				receiveDNS(t, stopped)
				select {
				case <-done:
					t.Fatal("returned before both queries completed")
				default:
				}
				if mode == "https-first" {
					close(addressRelease)
				} else {
					close(httpsRelease)
				}
			}
			err := receiveDNS(t, done)
			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation: %v", err)
				}
				receiveDNS(t, stopped)
			} else if err != nil {
				t.Fatal(err)
			}
			receiveDNS(t, stopped)
		})
	}
}

func TestDNSFlightAddressesDoNotInheritHTTPSTTL(t *testing.T) {
	var queries, addresses atomic.Int32
	d := newAlternativeDiscovery(func(context.Context, string) ([]HTTPSRecord, error) {
		queries.Add(1)
		return []HTTPSRecord{{Priority: 1, Target: ".", ALPN: []string{"h3"}, TTL: time.Hour}}, nil
	}, nil, false)
	d.addressLookup = func(context.Context, string) ([]net.IPAddr, error) {
		addresses.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	route, ok := d.resolve(t.Context(), "origin.test:443")
	if !ok || route.resolved == nil {
		t.Fatal("missing flight-scoped address result")
	}
	if cached, _ := d.get("origin.test:443"); cached.resolved != nil {
		t.Fatal("address result cached under HTTPS TTL")
	}
	if binding, _ := d.binding("origin.test:443"); binding.resolved != nil {
		t.Fatal("binding cached addresses without their TTL")
	}
	d.result(route, nil)
	if d.actual[route.origin].resolved != nil {
		t.Fatal("connection history retained scoped addresses")
	}
	second, ok := d.resolve(t.Context(), "origin.test:443")
	if !ok || second.resolved != nil || queries.Load() != 1 || addresses.Load() != 1 {
		t.Fatal("cached metadata unexpectedly retained or re-queried addresses")
	}
	ctx := context.WithValue(t.Context(), alternativeRouteKey{}, route)
	ips, err := lookupResolvedAddresses(ctx, "ORIGIN.TEST.", nil)
	if err != nil || len(ips) != 1 || !ips[0].IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatal("lost scoped result")
	}
	ips, err = lookupResolvedAddresses(ctx, "127.0.0.2", nil)
	if err != nil || len(ips) != 1 || !ips[0].IP.Equal(net.ParseIP("127.0.0.2")) {
		t.Fatal("reused addresses for a different target")
	}
}

func TestDNSAddressMetadataPreservesAltUsedAuthority(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://origin.test:443/", nil)
	if err != nil {
		t.Fatal(err)
	}
	route := alternativeRoute{origin: "origin.test:443", resolved: &resolvedAddresses{host: "origin.test"}}
	req = req.WithContext(context.WithValue(req.Context(), alternativeRouteKey{}, route))
	tr := &Transport{altUsed: true, discovery: newAlternativeDiscovery(nil, nil, false)}
	if got := tr.requestWithAltUsed(req).Header.Get("Alt-Used"); got != "origin.test" {
		t.Fatalf("lost direct authority after DNS prefetch: %q", got)
	}
}
