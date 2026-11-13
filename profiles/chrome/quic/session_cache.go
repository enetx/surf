package quic

import (
	"cmp"
	"crypto/tls"
	"encoding/binary"
	"slices"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/pkg/tlscache"
	"github.com/enetx/surf/profiles"
)

// ConfigureSessionCache follows QUICHE's two-ticket stack and invalidates older
// tickets when remembered transport state changes. RTT is not compatibility
// state and must not invalidate otherwise equivalent tickets.
// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/crypto/quic_client_session_cache.cc
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

			group = binary.BigEndian.AppendUint64(group, uint64(len(info.TransportParameters)))
			group = append(group, info.TransportParameters...)

			if settings, known := http3.ClientSessionSettings(state); known {
				group = append(group, 1)
				group = binary.BigEndian.AppendUint64(group, uint64(settings.MaxFieldSectionSize+1))

				var capabilities byte
				if settings.EnableDatagrams {
					capabilities |= 1
				}

				if settings.EnableExtendedConnect {
					capabilities |= 2
				}

				group = append(group, capabilities)
				var fields [][2]uint64

				settings.Other.Iter().ForEach(func(id, value uint64) { fields = append(fields, [2]uint64{id, value}) })
				slices.SortFunc(fields, func(a, b [2]uint64) int { return cmp.Compare(a[0], b[0]) })

				for _, field := range fields {
					group = binary.BigEndian.AppendUint64(group, field[0])
					group = binary.BigEndian.AppendUint64(group, field[1])
				}
			} else {
				group = append(group, 0)
			}

			return string(group)
		})
}
