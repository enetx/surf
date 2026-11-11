package h3transport

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

type resolvedAddresses struct {
	host string
	ips  []net.IPAddr
	err  error
}

func (r *resolvedAddresses) matches(host string) bool {
	return r != nil && strings.EqualFold(strings.TrimSuffix(r.host, "."), strings.TrimSuffix(host, "."))
}

// resolveDNS starts address and HTTPS queries together. Address results belong
// to this discovery flight only: net.Resolver does not expose their TTL, so they
// must not be cached for the HTTPS record's lifetime.
func (d *alternativeDiscovery) resolveDNS(ctx context.Context, query, host string) ([]HTTPSRecord, *resolvedAddresses, error) {
	if d.addressLookup == nil {
		records, err := d.lookup(ctx, query)
		return records, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type addressResult struct {
		resolved *resolvedAddresses
		elapsed  time.Duration
	}
	addressDone := make(chan addressResult, 1)
	go func() {
		start := time.Now()
		ips, err := d.addressLookup(ctx, host)
		addressDone <- addressResult{&resolvedAddresses{host: host, ips: ips, err: err}, time.Since(start)}
	}()
	type httpsResult struct {
		records []HTTPSRecord
		err     error
	}
	httpsCtx, cancelHTTPS := context.WithCancel(ctx)
	defer cancelHTTPS()
	httpsDone := make(chan httpsResult, 1)
	go func() { records, err := d.lookup(httpsCtx, query); httpsDone <- httpsResult{records, err} }()

	var result httpsResult
	var addresses *resolvedAddresses
	var timer *time.Timer
	var timeout <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for addressDone != nil || httpsDone != nil {
		select {
		case <-ctx.Done():
			return nil, nil, context.Cause(ctx)
		case a := <-addressDone:
			addresses = a.resolved
			addressDone = nil
			if httpsDone != nil && d.httpsWait != nil {
				if wait := d.httpsWait(a.elapsed); wait > 0 {
					timer = time.NewTimer(wait)
					timeout = timer.C
				}
			}
		case result = <-httpsDone:
			httpsDone = nil
			timeout = nil
		case <-timeout:
			select {
			case result = <-httpsDone:
				httpsDone = nil
				timeout = nil
				continue
			default:
			}
			// Only optional HTTPS metadata times out. Keep the completed address
			// result and the caller's context for its normal TCP connection.
			cancelHTTPS()
			return nil, addresses, errors.New("optional HTTPS lookup exceeded its supplemental wait")
		}
	}
	return result.records, addresses, result.err
}

func lookupResolvedAddresses(ctx context.Context, host string, resolver *net.Resolver) ([]net.IPAddr, error) {
	if route, ok := ctx.Value(alternativeRouteKey{}).(alternativeRoute); ok && route.resolved.matches(host) {
		return route.resolved.ips, route.resolved.err
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupIPAddr(ctx, host)
}
