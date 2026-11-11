package connrace

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type addressTestConn struct {
	net.Conn
	closed chan struct{}
	count  atomic.Int32
}

func (c *addressTestConn) Close() error {
	if c.count.Add(1) == 1 {
		close(c.closed)
	}
	return nil
}

func TestDialAddressesAdvancesInOrder(t *testing.T) {
	for _, delay := range []time.Duration{-1, time.Hour} {
		t.Run(delay.String(), func(t *testing.T) {
			var order []string
			want := &addressTestConn{closed: make(chan struct{})}
			got, err := DialAddresses(t.Context(), "tcp", []string{"one", "two", "three"}, delay,
				func(_ context.Context, _ string, address string) (net.Conn, error) {
					order = append(order, address)
					if address == "two" {
						return want, nil
					}
					return nil, errors.New("unreachable")
				})
			if err != nil || got != want || len(order) != 2 || order[0] != "one" || order[1] != "two" {
				t.Fatalf("order=%v error=%v", order, err)
			}
			got.Close()
		})
	}
}

func TestDialAddressesClosesConcurrentLosers(t *testing.T) {
	connections := []*addressTestConn{{closed: make(chan struct{})}, {closed: make(chan struct{})}, {closed: make(chan struct{})}}
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := DialAddresses(t.Context(), "tcp", []string{"0", "1", "2"}, 0,
			func(_ context.Context, _, address string) (net.Conn, error) {
				started <- struct{}{}
				<-release
				return connections[int(address[0]-'0')], nil
			})
		done <- result{conn, err}
	}()
	for range 3 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("candidate did not start")
		}
	}
	close(release)
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	r.conn.Close()
	for _, conn := range connections {
		select {
		case <-conn.closed:
		case <-time.After(3 * time.Second):
			t.Fatal("connection leaked")
		}
		if conn.count.Load() != 1 {
			t.Fatal("connection closed more than once")
		}
	}
}

func TestDialAddressesCancellationAndErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := DialAddresses(ctx, "tcp", []string{"one", "two"}, time.Hour,
			func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				return nil, context.Cause(ctx)
			})
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	sentinel := errors.New("dial failed")
	_, err := DialAddresses(t.Context(), "tcp", []string{"one", "two"}, -1, func(context.Context, string, string) (net.Conn, error) { return nil, sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatal("lost dial failure")
	}
	if _, err := DialAddresses(t.Context(), "tcp", nil, 0, nil); err == nil {
		t.Fatal("accepted empty address list")
	}
}
