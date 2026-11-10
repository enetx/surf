package main

import (
	"container/heap"
	"time"
)

type networkOptions struct {
	Jitter       time.Duration
	ReorderEvery uint64
	ReorderDelay time.Duration
}

type scheduledPackets []networkPacket

func (q scheduledPackets) Len() int { return len(q) }
func (q scheduledPackets) Less(i, j int) bool {
	if q[i].ready.Equal(q[j].ready) {
		return q[i].ordinal < q[j].ordinal
	}
	return q[i].ready.Before(q[j].ready)
}
func (q scheduledPackets) Swap(i, j int)   { q[i], q[j] = q[j], q[i] }
func (q *scheduledPackets) Push(value any) { *q = append(*q, value.(networkPacket)) }
func (q *scheduledPackets) Pop() any {
	last := len(*q) - 1
	value := (*q)[last]
	(*q)[last] = networkPacket{}
	*q = (*q)[:last]
	return value
}

func (c *shapedUDP) schedule(queue <-chan networkPacket, outgoing bool) {
	if c.options.Jitter == 0 && c.options.ReorderEvery == 0 {
		c.scheduleFIFO(queue, outgoing)
		return
	}
	defer c.wg.Done()
	var pending scheduledPackets
	for {
		var timer *time.Timer
		var expired <-chan time.Time
		if len(pending) > 0 {
			if !pending[0].ready.After(time.Now()) {
				if !c.deliver(heap.Pop(&pending).(networkPacket), outgoing) {
					return
				}
				continue
			}
			timer = time.NewTimer(time.Until(pending[0].ready))
			expired = timer.C
		}
		// Bound pending storage as well as the socket admission queue.
		input := queue
		if len(pending) >= cap(queue) {
			input = nil
		}
		select {
		case packet := <-input:
			heap.Push(&pending, packet)
		case <-expired:
		case <-c.closed:
			if timer != nil {
				timer.Stop()
			}
			return
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *shapedUDP) deliver(packet networkPacket, outgoing bool) bool {
	if outgoing {
		if _, err := c.PacketConn.WriteTo(packet.data, packet.addr); err != nil {
			c.stop(err)
			return false
		}
	} else {
		select {
		case c.delivered <- packet:
		case <-c.closed:
			return false
		}
	}
	c.mu.Lock()
	flow := c.flows[packet.flow]
	flow.Delivered++
	if packet.sequence < flow.lastDelivered {
		flow.Reordered++
	}
	flow.lastDelivered = max(flow.lastDelivered, packet.sequence)
	c.mu.Unlock()
	return true
}
