package connrace

import (
	"context"
	"errors"
	"net"
	"time"
)

// DialAddresses consumes a single resolution result while retaining the TCP
// dialer's configured fallback delay. Every successful losing connection closes.
func DialAddresses(ctx context.Context, network string, addresses []string, delay time.Duration,
	dial func(context.Context, string, string) (net.Conn, error),
) (net.Conn, error) {
	if len(addresses) == 0 {
		return nil, errors.New("no addresses to dial")
	}

	if delay < 0 || len(addresses) < 2 {
		var errs []error
		for _, address := range addresses {
			conn, err := dial(ctx, network, address)
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		conn net.Conn
		err  error
	}

	results := make(chan result, len(addresses))
	started := 0

	start := func() {
		address := addresses[started]
		started++
		go func() {
			conn, err := dial(ctx, network, address)
			results <- result{conn, err}
		}()
	}

	start()
	timer := time.NewTimer(delay)
	defer timer.Stop()

	drain := func(remaining int) {
		go func() {
			for range remaining {
				loser := <-results
				if loser.conn != nil {
					loser.conn.Close()
				}
			}
		}()
	}

	var errs []error
	received := 0

	for received < started {
		select {
		case <-ctx.Done():
			cancel()
			drain(started - received)
			return nil, errors.Join(append(errs, context.Cause(ctx))...)
		case r := <-results:
			received++
			if r.err == nil {
				cancel()
				drain(started - received)
				return r.conn, nil
			}
			errs = append(errs, r.err)
			if started < len(addresses) && ctx.Err() == nil {
				start()
				timer.Reset(delay)
			}
		case <-timer.C:
			if started < len(addresses) && ctx.Err() == nil {
				start()
				timer.Reset(delay)
			}
		}
	}

	return nil, errors.Join(errs...)
}
