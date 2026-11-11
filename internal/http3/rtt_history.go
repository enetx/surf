package h3transport

import (
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/transportparams"
	quictransport "github.com/enetx/surf/internal/quic"
)

// The HTTP/3 pool requests Dial only when replacing its previous connection.
// Read that connection's final statistics synchronously here: CloseIdle and a
// peer shutdown cannot race an asynchronous cache-update goroutine. An active
// GOAWAY connection also remains readable while its last responses drain.
// Origin is the original authority, before Alt-Svc/address-hint routing.
type rttHistory struct {
	mu               sync.Mutex
	entries          map[string]*rttEntry
	serial           uint64
	closed           bool
	parameter        uint64
	minimum, maximum time.Duration
}

type rttEntry struct {
	sample func() time.Duration
	serial uint64
}

func (h *rttHistory) prepare(origin string, config *quic.Config) (*quic.Config, func(*quic.Conn, error)) {
	origin = strings.ToLower(origin)

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return config, func(*quic.Conn, error) {}
	}

	if h.entries == nil {
		h.entries = make(map[string]*rttEntry)
	}

	entry := h.entries[origin]
	if entry == nil {
		if len(h.entries) >= 256 {
			var oldest string
			var serial uint64 = ^uint64(0)
			for key, e := range h.entries {
				if e.serial < serial {
					oldest, serial = key, e.serial
				}
			}

			delete(h.entries, oldest)
		}

		entry = &rttEntry{}
		h.entries[origin] = entry
	}

	var measured time.Duration
	if entry.sample != nil {
		measured = entry.sample().Truncate(time.Microsecond)
	}

	h.serial++
	entry.serial = h.serial
	serial := entry.serial
	h.mu.Unlock()

	config = quictransport.CloneConfig(config)
	if config == nil {
		config = quictransport.DefaultConfig()
	}

	if config.ClientHandshake == nil {
		config.ClientHandshake = &quic.ClientHandshake{}
	}

	if measured > 0 {
		config.ClientHandshake.InitialRTT = max(h.minimum, min(h.maximum, measured))
	}

	quictransport.EditTransportParameters(config.ClientHandshake, func(layout *transportparams.Layout) {
		layout.Additional = slices.DeleteFunc(
			layout.Additional,
			func(p transportparams.Parameter) bool { return p.ID == h.parameter },
		)

		if measured > 0 {
			layout.Additional = append(
				layout.Additional,
				transportparams.Parameter{
					ID:    h.parameter,
					Value: quicvarint.Append(nil, uint64(measured.Microseconds())),
				},
			)
		}
	})

	return config, func(conn *quic.Conn, err error) {
		h.mu.Lock()
		defer h.mu.Unlock()

		if h.closed || h.entries[origin] != entry || entry.serial != serial {
			return
		}

		if _, ok := errors.AsType[*net.DNSError](err); ok {
			return
		} // No QUIC session was created.

		if err != nil {
			entry.sample = nil
			return
		}
		entry.sample = func() time.Duration { return measuredConnectionRTT(conn) }
	}
}

func measuredConnectionRTT(conn *quic.Conn) time.Duration {
	if conn == nil || !conn.ConnectionState().TLS.HandshakeComplete {
		return 0
	}
	stats := conn.ConnectionStats()
	// Token restoration alone is not a new RTT measurement.
	if !stats.RTTMeasured {
		return 0
	}
	return stats.SmoothedRTT
}

func (h *rttHistory) close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true
	h.entries = nil
}
