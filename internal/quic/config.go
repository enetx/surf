package quictransport

import (
	"slices"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/transportparams"
)

func CloneConfig(config *quic.Config) *quic.Config {
	if config == nil {
		return nil
	}

	copy := config.Clone()
	copy.Versions = slices.Clone(config.Versions)

	return copy
}

func DefaultConfig() *quic.Config {
	return &quic.Config{
		Versions:             []quic.Version{quic.Version1},
		EnableDatagrams:      true,
		HandshakeIdleTimeout: DefaultHandshakeTimeout,
		MaxIdleTimeout:       DefaultMaxIdleTimeout,
		KeepAlivePeriod:      DefaultKeepAlivePeriod,
	}
}

const (
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultMaxIdleTimeout   = 30 * time.Second
	DefaultKeepAlivePeriod  = 15 * time.Second
)

// The implemented legacy min_ack_delay is a protocol field, despite its residue.
func IsGreaseParameter(id uint64) bool { return id >= 27 && (id-27)%31 == 0 && id != 0xff02de1a }

// EditTransportParameters amends a fresh snapshot for each connection, retaining
// per-attempt randomization without mutating a factory's layout or slices.
func EditTransportParameters(h *quic.ClientHandshake, edit func(*transportparams.Layout)) {
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
