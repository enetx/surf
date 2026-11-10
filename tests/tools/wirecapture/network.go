package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// This is an application-level UDP path emulator, not a NIC or kernel netem
// capture. Constant one-way delay is pipelined; it does not sleep in WriteTo and
// accidentally impose a per-packet bandwidth limit. Loss counters start anew for
// each remote address and direction, so all clients receive the same rule.
type networkPacket struct {
	data  []byte
	addr  net.Addr
	ready time.Time
	flow  string
}

type networkFlow struct {
	Seen, Dropped, Overflow, Delivered uint64
}

type shapedUDP struct {
	net.PacketConn
	delay           time.Duration
	dropEvery       uint64
	dropFirst       uint64
	logger          *os.File
	closed          chan struct{}
	once            sync.Once
	wg              sync.WaitGroup
	in, out         chan networkPacket
	delivered       chan networkPacket
	mu              sync.Mutex
	flows           map[string]*networkFlow
	err             error
	readBy, writeBy time.Time
	changed         chan struct{}
}

func newShapedUDP(base net.PacketConn, delay time.Duration, dropEvery, dropFirst uint64, logger *os.File) *shapedUDP {
	c := &shapedUDP{PacketConn: base, delay: delay, dropEvery: dropEvery, dropFirst: dropFirst, logger: logger,
		closed: make(chan struct{}), changed: make(chan struct{}), flows: make(map[string]*networkFlow),
		in: make(chan networkPacket, 4096), out: make(chan networkPacket, 4096), delivered: make(chan networkPacket, 4096)}
	c.wg.Add(3)
	go c.receive()
	go c.schedule(c.in, false)
	go c.schedule(c.out, true)
	return c
}

func (c *shapedUDP) packet(data []byte, addr net.Addr, direction string) (networkPacket, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := direction + "|" + addr.String()
	flow := c.flows[key]
	if flow == nil {
		flow = new(networkFlow)
		c.flows[key] = flow
	}
	flow.Seen++
	drop := flow.Seen <= c.dropFirst || c.dropEvery > 0 && (flow.Seen-c.dropFirst)%c.dropEvery == 0
	if drop {
		flow.Dropped++
	}
	if c.logger != nil {
		err := json.NewEncoder(c.logger).Encode(map[string]any{"time": time.Now().UTC(), "direction": direction, "remote": addr.String(), "sequence": flow.Seen, "dropped": drop, "bytes": len(data)})
		if err != nil && c.err == nil {
			c.err = err
		}
	}
	if drop {
		return networkPacket{}, true
	}
	copyAddr := *addr.(*net.UDPAddr)
	copyAddr.IP = bytes.Clone(copyAddr.IP)
	return networkPacket{data: bytes.Clone(data), addr: &copyAddr, ready: time.Now().Add(c.delay), flow: key}, false
}

func (c *shapedUDP) receive() {
	defer c.wg.Done()
	buffer := make([]byte, 65535)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buffer)
		if err != nil {
			c.stop(err)
			return
		}
		packet, drop := c.packet(buffer[:n], addr, "incoming")
		if drop {
			continue
		}
		select {
		case c.in <- packet:
		case <-c.closed:
			return
		default:
			c.mu.Lock()
			c.flows[packet.flow].Overflow++
			c.mu.Unlock()
		}
	}
}

func (c *shapedUDP) schedule(queue <-chan networkPacket, outgoing bool) {
	defer c.wg.Done()
	for {
		var packet networkPacket
		select {
		case packet = <-queue:
		case <-c.closed:
			return
		}
		if duration := time.Until(packet.ready); duration > 0 {
			timer := time.NewTimer(duration)
			select {
			case <-timer.C:
			case <-c.closed:
				timer.Stop()
				return
			}
		}
		if outgoing {
			if _, err := c.PacketConn.WriteTo(packet.data, packet.addr); err != nil {
				c.stop(err)
				return
			}
		} else {
			select {
			case c.delivered <- packet:
			case <-c.closed:
				return
			}
		}
		c.mu.Lock()
		c.flows[packet.flow].Delivered++
		c.mu.Unlock()
	}
}

func (c *shapedUDP) deadlines(read bool) (time.Time, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if read {
		return c.readBy, c.changed
	}
	return c.writeBy, c.changed
}

func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(max(0, time.Until(deadline)))
	return timer, timer.C
}

func (c *shapedUDP) ReadFrom(buffer []byte) (int, net.Addr, error) {
	for {
		deadline, changed := c.deadlines(true)
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timer, expired := deadlineTimer(deadline)
		var packet networkPacket
		var err error
		select {
		case packet = <-c.delivered:
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-expired:
			err = os.ErrDeadlineExceeded
		case <-c.closed:
			err = net.ErrClosed
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return 0, nil, err
		}
		return copy(buffer, packet.data), packet.addr, nil
	}
}

func (c *shapedUDP) WriteTo(data []byte, addr net.Addr) (int, error) {
	deadline, _ := c.deadlines(false)
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	packet, drop := c.packet(data, addr, "outgoing")
	if drop {
		return len(data), nil
	}
	for {
		deadline, changed := c.deadlines(false)
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		timer, expired := deadlineTimer(deadline)
		var err error
		select {
		case c.out <- packet:
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-expired:
			err = os.ErrDeadlineExceeded
		case <-c.closed:
			err = net.ErrClosed
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return 0, err
		}
		return len(data), nil
	}
}

func (c *shapedUDP) stop(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		if err != nil && !errors.Is(err, net.ErrClosed) && c.err == nil {
			c.err = err
		}
		c.mu.Unlock()
		close(c.closed)
		c.PacketConn.Close()
	})
}

func (c *shapedUDP) Close() error                       { c.stop(nil); c.wg.Wait(); return nil }
func (c *shapedUDP) SetReadDeadline(t time.Time) error  { return c.setDeadline(t, true, false) }
func (c *shapedUDP) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }
func (c *shapedUDP) SetDeadline(t time.Time) error      { return c.setDeadline(t, true, true) }
func (c *shapedUDP) setDeadline(t time.Time, read, write bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if read {
		c.readBy = t
	}
	if write {
		c.writeBy = t
	}
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}

func (c *shapedUDP) summary() any {
	c.mu.Lock()
	defer c.mu.Unlock()
	flows := make(map[string]networkFlow, len(c.flows))
	for key, flow := range c.flows {
		flows[key] = *flow
	}
	return map[string]any{"one_way_delay_ms": c.delay.Milliseconds(), "drop_every_per_flow_direction": c.dropEvery, "drop_first_per_flow_direction": c.dropFirst, "flows": flows, "error": func() string {
		if c.err != nil {
			return c.err.Error()
		}
		return ""
	}()}
}

func (c *shapedUDP) SetReadBuffer(n int) error {
	if setter, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return setter.SetReadBuffer(n)
	}
	return errors.ErrUnsupported
}
func (c *shapedUDP) SetWriteBuffer(n int) error {
	if setter, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return setter.SetWriteBuffer(n)
	}
	return errors.ErrUnsupported
}
