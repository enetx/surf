package surf

import (
	"errors"

	"github.com/enetx/quic-go"
	"github.com/enetx/surf/internal/quictls"
	"github.com/enetx/surf/internal/specclone"
	utls "github.com/refraction-networking/utls"
)

// ClientHandshake sets optional QUIC handshake controls. The supplied values are
// snapshotted; nil removes this override and retains any QUICConfig controls.
func (h *HTTP3Settings) ClientHandshake(config *quic.ClientHandshake) *HTTP3Settings {
	h.clientHandshake = config.Clone()
	return h
}

// ClientHelloSpec sets an explicit QUIC ClientHello template. It must contain
// QUICTransportParametersExtension and ALPNExtension; TCP templates are rejected.
// QUIC supplies real transport parameters and the HTTP/3 ALPN for each dial.
// Browser TCP JA settings remain independent. Nil restores standard crypto/tls.
func (h *HTTP3Settings) ClientHelloSpec(spec *utls.ClientHelloSpec) *HTTP3Settings {
	if spec == nil {
		h.clientHelloFactory = nil
		return h
	}

	snapshot := specclone.Clone(spec)
	h.clientHelloFactory = func() (utls.ClientHelloSpec, error) { return *specclone.Clone(snapshot), nil }

	return h
}

// ClientHelloFactory supplies a fresh QUIC template per connection attempt,
// including retries after version negotiation. The factory may run concurrently.
// Returned templates must not share mutable extensions with other attempts.
func (h *HTTP3Settings) ClientHelloFactory(factory func() (utls.ClientHelloSpec, error)) *HTTP3Settings {
	h.clientHelloFactory = factory
	return h
}

func (h *HTTP3Settings) configureClientHandshake(config *quic.Config) error {
	if h.clientHandshake != nil {
		config.ClientHandshake = h.clientHandshake.Clone()
	}

	if h.clientHelloFactory == nil {
		return nil
	}

	if config.ClientHandshake == nil {
		config.ClientHandshake = &quic.ClientHandshake{}
	}

	if config.ClientHandshake.NewTLSClient != nil {
		return errors.New("configure either ClientHelloSpec/Factory or ClientHandshake.NewTLSClient")
	}

	config.ClientHandshake.NewTLSClient = quictls.Factory(h.clientHelloFactory)

	return nil
}
