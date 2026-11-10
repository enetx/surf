package surf

import (
	"bytes"
	"slices"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/tlsquic"
	"github.com/enetx/quic-go/transportparams"
	utls "github.com/refraction-networking/utls"
)

func (q *QUICSettings) handshake() *quic.ClientHandshake {
	if q.http3.clientHandshake == nil {
		q.http3.clientHandshake = q.config().ClientHandshake.Clone()

		if q.http3.clientHandshake == nil {
			q.http3.clientHandshake = &quic.ClientHandshake{}
		}
	}

	return q.http3.clientHandshake
}

// StreamReceiveWindows sets initial bidirectional-local, bidirectional-remote
// and unidirectional receive windows. Zero explicitly advertises zero credit.
func (q *QUICSettings) StreamReceiveWindows(bidiLocal, bidiRemote, uni uint64) *QUICSettings {
	q.handshake().StreamReceiveWindows = &quic.StreamReceiveWindows{
		BidiLocal: bidiLocal, BidiRemote: bidiRemote, Uni: uni,
	}

	return q
}

// ClientHelloSpec snapshots an explicit QUIC TLS template. Nil restores standard TLS.
func (q *QUICSettings) ClientHelloSpec(spec *utls.ClientHelloSpec) *QUICSettings {
	q.http3.ClientHelloSpec(spec)
	return q
}

// ClientHelloFactory supplies a fresh QUIC TLS template per connection attempt.
// It may run concurrently; templates must not share mutable extensions.
func (q *QUICSettings) ClientHelloFactory(factory func() (utls.ClientHelloSpec, error)) *QUICSettings {
	q.http3.ClientHelloFactory(factory)
	return q
}

// TLSClientFactory sets a custom QUIC TLS engine. Configure either this factory
// or ClientHelloSpec/ClientHelloFactory; using both returns an error.
func (q *QUICSettings) TLSClientFactory(factory tlsquic.NewClient) *QUICSettings {
	q.handshake().NewTLSClient = factory
	return q
}

// MaxUDPPayloadSize sets the advertised UDP payload limit and actual receive size.
// It also enables advertising this parameter after OmitMaxUDPPayloadSize(true).
func (q *QUICSettings) MaxUDPPayloadSize(size uint64) *QUICSettings {
	h := q.handshake()
	h.MaxUDPPayloadSize = size
	h.OmitMaxUDPPayloadSize = false

	return q
}

// OmitMaxUDPPayloadSize omits the parameter and provisions the protocol default
// receive size when enabled. False advertises the current payload limit.
func (q *QUICSettings) OmitMaxUDPPayloadSize(omit bool) *QUICSettings {
	h := q.handshake()

	h.OmitMaxUDPPayloadSize = omit

	if omit {
		h.MaxUDPPayloadSize = quic.MaxUDPReceivePacketSize
	}

	return q
}

// MaxDatagramFrameSize sets the advertised QUIC datagram limit.
// Datagram support must also be enabled. Zero selects quic-go's default.
func (q *QUICSettings) MaxDatagramFrameSize(size uint64) *QUICSettings {
	q.handshake().MaxDatagramFrameSize = size
	return q
}

// MaxAckDelay sets the acknowledgment scheduling bound in whole milliseconds.
// Zero selects quic-go's default.
func (q *QUICSettings) MaxAckDelay(delay time.Duration) *QUICSettings {
	q.handshake().MaxAckDelay = delay
	return q
}

// ActiveConnectionIDLimit sets the receive-side connection ID limit (at least 2).
// Zero selects quic-go's default.
func (q *QUICSettings) ActiveConnectionIDLimit(limit uint64) *QUICSettings {
	q.handshake().ActiveConnectionIDLimit = limit
	return q
}

// OmitLegacyResetStreamAt controls advertising the legacy reliable-reset parameter.
func (q *QUICSettings) OmitLegacyResetStreamAt(omit bool) *QUICSettings {
	q.handshake().OmitLegacyResetStreamAt = omit
	return q
}

// InitialDestinationConnectionIDLength sets the Initial destination ID length.
// Nonzero lengths must be 8 through 20; zero selects quic-go's default.
func (q *QUICSettings) InitialDestinationConnectionIDLength(length int) *QUICSettings {
	q.handshake().InitialDestinationConnectionIDLength = length
	q.handshake().NewInitialDestinationConnectionIDLength = nil

	return q
}

// InitialDestinationConnectionIDLengthFactory chooses a fresh 8..20 byte length
// per connection. Nil restores the fixed length. The factory may run concurrently.
func (q *QUICSettings) InitialDestinationConnectionIDLengthFactory(factory func() (int, error)) *QUICSettings {
	q.handshake().NewInitialDestinationConnectionIDLength = factory
	return q
}

// InitialPacketNumber sets a fixed initial packet number and clears any factory.
func (q *QUICSettings) InitialPacketNumber(number uint64) *QUICSettings {
	h := q.handshake()

	h.InitialPacketNumber = number
	h.NewInitialPacketNumber = nil

	return q
}

// InitialPacketNumberFactory supplies a fresh initial number per connection.
// Nil restores the fixed number. The factory may run concurrently.
func (q *QUICSettings) InitialPacketNumberFactory(factory func() (uint64, error)) *QUICSettings {
	q.handshake().NewInitialPacketNumber = factory
	return q
}

// DisableClientHelloScrambling controls SNI/ECH CRYPTO fragmentation.
func (q *QUICSettings) DisableClientHelloScrambling(disabled bool) *QUICSettings {
	q.handshake().DisableClientHelloScrambling = disabled
	return q
}

// TransportParameterOrder sets preferred parameter order. Unlisted parameters
// follow in their original order. Use transportparams.Grease for native GREASE.
// The order is copied and also applies to layouts generated by a browser factory.
func (q *QUICSettings) TransportParameterOrder(ids ...uint64) *QUICSettings {
	order := slices.Clone(ids)
	q.editTransportParameters(func(layout *transportparams.Layout) {
		layout.Order = slices.Clone(order)
	})

	return q
}

// TransportParameter adds or replaces an extension parameter with wire-encoded
// bytes. The value is copied. Engine-owned parameters must use their own setters.
// Advertising a parameter does not implement an extension protocol.
func (q *QUICSettings) TransportParameter(id uint64, value []byte) *QUICSettings {
	value = bytes.Clone(value)
	q.editTransportParameters(func(layout *transportparams.Layout) {
		parameter := transportparams.Parameter{ID: id, Value: bytes.Clone(value)}

		for i := range layout.Additional {
			if layout.Additional[i].ID == id {
				layout.Additional[i] = parameter

				return
			}
		}

		layout.Additional = append(layout.Additional, parameter)
	})

	return q
}

// DisableTransportParameterGrease controls reserved transport parameters,
// including those supplied by a browser factory. False uses native QUIC GREASE.
func (q *QUICSettings) DisableTransportParameterGrease(disabled bool) *QUICSettings {
	q.editTransportParameters(func(layout *transportparams.Layout) {
		layout.DisableGrease = disabled
		layout.Additional = slices.DeleteFunc(layout.Additional, func(p transportparams.Parameter) bool {
			return isQUICGreaseParameter(p.ID)
		})

		order := layout.Order[:0]
		seen := false

		for _, id := range layout.Order {
			if id == transportparams.Grease || isQUICGreaseParameter(id) {
				if disabled || seen {
					continue
				}

				id, seen = transportparams.Grease, true
			}

			order = append(order, id)
		}

		layout.Order = order
	})

	return q
}

// The implemented legacy min_ack_delay is a protocol field, despite its residue.
func isQUICGreaseParameter(id uint64) bool { return id >= 27 && (id-27)%31 == 0 && id != 0xff02de1a }

// TransportParametersFactory supplies a layout per handshake attempt, replacing
// any previous factory and its edits. Later layout setters amend its result.
// The factory may run concurrently. Nil restores the static layout.
func (q *QUICSettings) TransportParametersFactory(
	factory func(quic.Version) (*transportparams.Layout, error),
) *QUICSettings {
	q.handshake().NewTransportParameters = factory
	return q
}

// Amend a fresh snapshot for every connection, retaining per-attempt browser
// randomization and never mutating a factory's returned layout or its slices.
func (q *QUICSettings) editTransportParameters(edit func(*transportparams.Layout)) {
	h := q.handshake()

	if factory := h.NewTransportParameters; factory != nil {
		h.NewTransportParameters = func(version quic.Version) (*transportparams.Layout, error) {
			layout, err := factory(version)
			if err != nil {
				return nil, err
			}

			layout = layout.Clone()
			if layout == nil {
				layout = &transportparams.Layout{}
			}

			edit(layout)

			return layout, nil
		}

		return
	}

	if h.TransportParameters == nil {
		h.TransportParameters = &transportparams.Layout{}
	}

	edit(h.TransportParameters)
}
