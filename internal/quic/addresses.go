package quictransport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/enetx/quic-go"
)

func (ut *Dialer) resolveAddresses(ctx context.Context, address string, hints []netip.Addr) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if net.ParseIP(host) != nil {
		return []string{address}, nil
	}

	resolver := net.DefaultResolver
	if ut.NetDialer != nil && ut.NetDialer.Resolver != nil {
		resolver = ut.NetDialer.Resolver
	}

	ips, lookupErr := resolver.LookupIPAddr(ctx, host)
	var addresses []string
	for _, ip := range ips {
		host := ip.IP.String()
		if ip.Zone != "" {
			host += "%" + ip.Zone
		}

		addresses = append(addresses, net.JoinHostPort(host, port))
	}

	for _, hint := range hints {
		if hint.IsValid() && !hint.IsUnspecified() && !hint.IsMulticast() {
			candidate := net.JoinHostPort(hint.String(), port)
			if !slices.Contains(addresses, candidate) {
				addresses = append(addresses, candidate)
			}
		}
	}

	if len(addresses) == 0 {
		if lookupErr != nil {
			return nil, lookupErr
		}
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	return addresses[:min(len(addresses), 16)], nil
}

func (ut *Dialer) dialAddresses(
	ctx context.Context,
	addresses []string,
	tlsConfig *tls.Config,
	config *quic.Config,
	early bool,
) (*quic.Conn, error) {
	attempt := func(ctx context.Context, address string) (*quic.Conn, error) {
		if ut.Proxy != "" {
			return ut.dialSOCKS5(ctx, address, tlsConfig.Clone(), config, early)
		}
		return ut.dialDirect(ctx, address, tlsConfig.Clone(), config, early)
	}

	if ut.AddressFallbackDelay <= 0 || len(addresses) == 1 {
		var errs []error
		for _, address := range addresses {
			conn, err := attempt(ctx, address)
			if err == nil {
				return conn, nil
			}

			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
		}

		return nil, errors.Join(errs...)
	}

	type result struct {
		conn *quic.Conn
		err  error
	}

	racingCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan result, len(addresses))
	advance := make(chan struct{}, len(addresses))

	for i, address := range addresses {
		go func() {
			if i > 0 {
				timer := time.NewTimer(time.Duration(i) * ut.AddressFallbackDelay)
				defer timer.Stop()

				select {
				case <-timer.C:
				case <-advance:
				case <-racingCtx.Done():
					results <- result{err: context.Cause(racingCtx)}
					return
				}
			}

			conn, err := attempt(racingCtx, address)
			results <- result{conn, err}
		}()
	}

	var errs []error
	for received := range addresses {
		r := <-results
		if r.err == nil {
			cancel()
			// Every worker reports exactly once, including canceled timers. Close
			// a concurrently successful loser instead of leaking a live session.
			remaining := len(addresses) - received - 1

			go func() {
				for range remaining {
					other := <-results
					if other.conn != nil {
						other.conn.CloseWithError(0, "")
					}
				}
			}()

			return r.conn, nil
		}

		errs = append(errs, r.err)

		select {
		case advance <- struct{}{}:
		default:
		}
	}

	return nil, errors.Join(errs...)
}
