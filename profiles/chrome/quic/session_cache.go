package quic

import (
	"crypto/tls"
	"encoding/binary"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf/pkg/tlscache"
	"github.com/enetx/surf/profiles"
)

// ConfigureSessionCache follows QUICHE's two-ticket stack and invalidates older
// tickets when remembered transport state changes. RTT is not compatibility
// state and must not invalidate otherwise equivalent tickets.
// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/crypto/quic_client_session_cache.cc
func ConfigureSessionCache(cache *profiles.SessionCacheConfig) {
	cache.Capacity(1024).TicketsPerKey(2).
		Order(tlscache.NewestFirst).DiscardOnExpiry(true).ClearEarlyDataOnReject(true).
		Group(func(state *tls.ClientSessionState) string {
			info, ok := quic.ClientSessionMetadata(state)
			if !ok {
				return "unmarked"
			}

			group := binary.BigEndian.AppendUint32(nil, uint32(info.Version))
			group = append(group, byte(len(info.ConnectionID)))
			group = append(group, info.ConnectionID...)

			return string(append(group, info.TransportParameters...))
		})
}
