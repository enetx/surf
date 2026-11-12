// Package tlscache provides bounded TLS ticket queues for browser profiles and
// applications. It implements crypto/tls.ClientSessionCache; Surf bridges that
// same public cache to uTLS without exposing private TLS representations.
package tlscache

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/enetx/g"
)

// Order controls which available ticket a lookup consumes.
type Order uint8

const (
	// NewestFirst selects the most recently inserted ticket.
	NewestFirst Order = iota
	// EarliestExpiryFirst selects the nearest expiry; new equal-expiry tickets go first.
	EarliestExpiryFirst
)

// Builder configures an immutable cache policy. Build creates fresh cache state.
type Builder struct {
	capacity, tickets int                                  // Bounds retained keys and queued tickets per key.
	order             Order                                // Selection order within each key.
	reuseTLS12        bool                                 // Retain selected legacy tickets.
	discardOnExpiry   bool                                 // Expire all tickets when the next one is invalid.
	skipExpired       bool                                 // Continue a lookup after individually discarding an expired ticket.
	clearEarlyData    bool                                 // Strip early-data permission from pending tickets after rejection.
	clock             func() time.Time                     // Validity clock, called outside cache locks.
	group             func(*tls.ClientSessionState) string // Compatibility key, called outside locks.
}

// New starts a cache policy with 64 keys, one ticket per key, newest-first
// selection, individual expired-ticket skipping and time.Now. TLS 1.2 reuse,
// whole-entry expiry, early-data clearing and compatibility grouping are off.
func New() *Builder { return &Builder{capacity: 64, tickets: 1, skipExpired: true, clock: time.Now} }

// Capacity bounds server keys, including recently consumed-ticket records.
// The valid range is 1..1048576; the default is 64.
func (b *Builder) Capacity(keys int) *Builder { b.capacity = keys; return b }

// TicketsPerKey bounds available tickets for each opaque TLS cache key.
// The valid range is 1..1024; the default is one.
func (b *Builder) TicketsPerKey(tickets int) *Builder { b.tickets = tickets; return b }

// Order selects ticket retrieval order. The default is NewestFirst.
func (b *Builder) Order(order Order) *Builder { b.order = order; return b }

// ReuseTLS12 keeps legacy tickets reusable. TLS 1.3 tickets are always consumed.
func (b *Builder) ReuseTLS12(enabled bool) *Builder { b.reuseTLS12 = enabled; return b }

// DiscardOnExpiry discards the entire key when its next ticket expires.
// Otherwise individual expiry handling follows SkipExpired. Disabled by default.
func (b *Builder) DiscardOnExpiry(enabled bool) *Builder { b.discardOnExpiry = enabled; return b }

// SkipExpired continues lookup after removing an expired ticket. False returns
// a miss for that lookup and leaves the next ticket for a later connection.
// DiscardOnExpiry takes precedence when enabled.
func (b *Builder) SkipExpired(enabled bool) *Builder { b.skipExpired = enabled; return b }

// ClearEarlyDataOnReject disables 0-RTT on the remaining tickets for a server
// after RejectEarlyData is called. TLS resumption itself remains available.
func (b *Builder) ClearEarlyDataOnReject(enabled bool) *Builder { b.clearEarlyData = enabled; return b }

// Clock supplies the cache's validity clock. Nil restores time.Now.
func (b *Builder) Clock(clock func() time.Time) *Builder {
	if clock == nil {
		clock = time.Now
	}
	b.clock = clock
	return b
}

// Group invalidates queued tickets when remembered application/transport state
// changes. Nil permits all states. The callback runs outside cache locks and
// must be concurrency safe; it must not modify the supplied session.
func (b *Builder) Group(group func(*tls.ClientSessionState) string) *Builder {
	b.group = group
	return b
}

// Build validates the policy and creates independent cache state. Later
// changes to the builder do not change an existing cache. Invalid capacities,
// ticket limits or ordering are returned as an error.
func (b *Builder) Build() g.Result[*Cache] {
	if b.capacity < 1 || b.capacity > 1<<20 || b.tickets < 1 || b.tickets > 1024 || b.order > EarliestExpiryFirst {
		return g.Err[*Cache](fmt.Errorf("invalid TLS cache capacity, ticket limit or ordering"))
	}
	if b.clock == nil {
		b.clock = time.Now
	}
	return g.Ok(newCache(*b))
}
