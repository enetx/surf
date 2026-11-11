package h3transport

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/surf/internal/connrace"
)

var (
	errHTTPSNoTCP          = errors.New("surf: HTTPS service binding does not permit TCP")
	errHTTPSBindingExpired = errors.New("surf: HTTPS ECH binding expired and DNS refresh failed")
)

func bindingSupportsTCP(r *HTTPSRecord, version int) bool {
	if !r.NoDefaultALPN {
		return true
	}

	protocol := "h2"
	if version == 1 {
		protocol = "http/1.1"
	}

	return slices.Contains(r.ALPN, protocol)
}

// DNS service bindings retain their original TTL independently of alternative
// connection backoff. In particular, a broken QUIC address must not erase ECH
// before the TCP backup or the next request.
type httpsServiceBinding struct {
	alternativeRoute
	tcp bool
}

func bindingTransports(r *HTTPSRecord) (h3, tcp bool) {
	// RFC 9460 sections 7.1.2 and 9: default ALPN adds the TCP transport;
	// once a transport is selected its full normal ALPN list is offered.
	tcp = !r.NoDefaultALPN

	for _, alpn := range r.ALPN {
		switch alpn {
		case "h3":
			h3 = true
		case "h2", "http/1.1":
			tcp = true
		}
	}

	return h3, tcp
}

func (d *alternativeDiscovery) putBinding(binding httpsServiceBinding) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.bindings[binding.origin]; !exists && len(d.bindings) >= 256 {
		for origin := range d.bindings {
			delete(d.bindings, origin)
			// An evicted binding must be looked up again, not hidden by the
			// negative-query throttle while its TLS policy is forgotten.
			delete(d.dnsUntil, origin)

			if route, ok := d.entries[origin]; ok && !route.fromAltSvc {
				delete(d.entries, origin)
			}

			break
		}
	}

	d.bindings[binding.origin] = binding
	d.dnsUntil[binding.origin] = binding.expires
}

func (d *alternativeDiscovery) binding(origin string) (httpsServiceBinding, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	binding, ok := d.bindings[origin]
	if !ok || !d.now().Before(binding.expires) {
		return httpsServiceBinding{}, false
	}

	return binding, true
}

func (d *alternativeDiscovery) needsDNSRefresh(origin string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	host, _, _ := net.SplitHostPort(origin)
	if d.lookup == nil || net.ParseIP(host) != nil {
		return false
	}

	return !d.now().Before(d.dnsUntil[origin])
}

func (d *alternativeDiscovery) expiredECH(origin string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	binding, ok := d.bindings[origin]

	return ok && len(binding.ech) > 0 && !d.now().Before(binding.expires)
}

func (d *alternativeDiscovery) clearBinding(origin string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.bindings, origin)

	if route, ok := d.entries[origin]; ok && !route.fromAltSvc {
		delete(d.entries, origin)
	}
}

func (ut *Transport) preconnectDiscoveredTCP(req *http.Request) error {
	if route, ok := req.Context().Value(alternativeRouteKey{}).(alternativeRoute); ok && route.noTCP {
		return errHTTPSNoTCP
	}

	return ut.preconnectTCP(req)
}

func TCPBindingDial(
	original func(context.Context, string, string) (net.Conn, error),
) func(context.Context, string, string) (net.Conn, error) {
	return tcpBindingDial(original, 0, false)
}

func tcpBindingDial(
	original func(context.Context, string, string) (net.Conn, error),
	fallbackDelay time.Duration,
	reuseResolved bool,
) func(context.Context, string, string) (net.Conn, error) {
	if original == nil {
		original = new(net.Dialer).DialContext
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		route, ok := ctx.Value(alternativeRouteKey{}).(alternativeRoute)
		if !ok || !strings.EqualFold(route.origin, address) {
			return original(ctx, network, address)
		}

		if route.noTCP {
			return nil, errHTTPSNoTCP
		}

		target := address

		if route.tcpAddress != "" {
			target = route.tcpAddress
		}

		host, port, _ := net.SplitHostPort(target)

		if reuseResolved && route.resolved.matches(host) {
			var addresses []string
			for _, ip := range route.resolved.ips {
				if ip.IP == nil || network == "tcp4" && ip.IP.To4() == nil || network == "tcp6" && ip.IP.To4() != nil {
					continue
				}

				host := ip.IP.String()
				if ip.Zone != "" {
					host += "%" + ip.Zone
				}

				addresses = append(addresses, net.JoinHostPort(host, port))
			}

			for _, hint := range route.hints {
				if !hint.IsValid() || hint.IsUnspecified() || hint.IsMulticast() ||
					network == "tcp4" && !hint.Is4() || network == "tcp6" && hint.Is4() {
					continue
				}

				candidate := net.JoinHostPort(hint.String(), port)
				if !slices.Contains(addresses, candidate) {
					addresses = append(addresses, candidate)
				}
			}

			if len(addresses) == 0 {
				if route.resolved.err != nil {
					return nil, route.resolved.err
				}

				return nil, &net.DNSError{Name: host, Err: "no addresses for requested network", IsNotFound: true}
			}

			delay := 300 * time.Millisecond // net.Dialer's default fallback delay.
			if fallbackDelay != 0 {
				delay = fallbackDelay
			}

			return connrace.DialAddresses(ctx, network, addresses[:min(len(addresses), 16)], delay, original)
		}

		if route.tcpAddress == "" {
			return original(ctx, network, address)
		}

		conn, err := original(ctx, network, route.tcpAddress)
		if err == nil {
			return conn, nil
		}

		if _, dnsError := errors.AsType[*net.DNSError](err); !dnsError {
			return nil, err
		}

		_, port, _ = net.SplitHostPort(route.tcpAddress)

		for _, hint := range route.hints {
			if !hint.IsValid() || hint.IsUnspecified() || hint.IsMulticast() {
				continue
			}

			conn, hintErr := original(ctx, network, net.JoinHostPort(hint.String(), port))
			if hintErr == nil {
				return conn, nil
			}

			if ctx.Err() != nil {
				return nil, context.Cause(ctx)
			}
		}

		return nil, err
	}
}

func ECHConfig(ctx context.Context) []byte {
	route, _ := ctx.Value(alternativeRouteKey{}).(alternativeRoute)
	return route.ech
}
