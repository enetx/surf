// Package quictls adapts the official uTLS QUIC API to the transport's event
// interface. Browser templates and policies are supplied by Surf, not QUIC.
package quictls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"

	"github.com/enetx/quic-go/tlsquic"
	"github.com/enetx/surf/internal/tlsstate"
	utls "github.com/refraction-networking/utls"
)

// Factory builds an independent client for each attempt.
// SessionState's private TLS fields never cross package layouts:
// the adapter retains the original uTLS state and forwards only public metadata.
func Factory(spec func() (utls.ClientHelloSpec, error)) tlsquic.NewClient {
	return func(config *tls.Config) (tlsquic.Conn, error) {
		if config.GetClientCertificate != nil {
			return nil, errors.New(
				"QUIC ClientHello adapter does not support dynamic GetClientCertificate; use Certificates",
			)
		}

		if config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13 || config.MinVersion > tls.VersionTLS13 {
			return nil, errors.New("QUIC requires TLS 1.3")
		}

		template, err := spec()
		if err != nil {
			return nil, err
		}

		foundParams, foundALPN := false, false

		for _, ext := range template.Extensions {
			switch e := ext.(type) {
			case *utls.QUICTransportParametersExtension:
				if foundParams {
					return nil, errors.New("duplicate QUIC transport parameters extension")
				}
				foundParams = true
			case *utls.ALPNExtension:
				foundALPN = true
				e.AlpnProtocols = slices.Clone(config.NextProtos)
			}
		}

		if !foundParams || !foundALPN {
			return nil, errors.New("QUIC ClientHello requires QUICTransportParametersExtension and ALPNExtension")
		}

		// Per-connection public configuration hooks let a custom extension bind
		// SNI-dependent wire state before ApplyPreset, without private TLS access.
		for _, extension := range template.Extensions {
			if prepare, ok := extension.(interface {
				PrepareClientHello(*utls.ClientHelloSpec, *tls.Config)
			}); ok {
				prepare.PrepareClientHello(&template, config)
			}
		}

		c := &utls.Config{
			Rand: config.Rand, Time: config.Time, RootCAs: config.RootCAs,
			ServerName: config.ServerName, NextProtos: slices.Clone(config.NextProtos),
			InsecureSkipVerify: config.InsecureSkipVerify, VerifyPeerCertificate: config.VerifyPeerCertificate,
			MinVersion: utls.VersionTLS13, MaxVersion: utls.VersionTLS13, KeyLogWriter: config.KeyLogWriter,
			SessionTicketsDisabled: config.SessionTicketsDisabled, OmitEmptyPsk: true,
			EncryptedClientHelloConfigList: slices.Clone(config.EncryptedClientHelloConfigList),
		}

		if config.ClientSessionCache != nil {
			c.ClientSessionCache = sessionCache{config.ClientSessionCache}
		}

		for _, cert := range config.Certificates {
			c.Certificates = append(
				c.Certificates,
				utls.Certificate{
					Certificate:                  cert.Certificate,
					PrivateKey:                   cert.PrivateKey,
					SupportedSignatureAlgorithms: signatureSchemes(cert.SupportedSignatureAlgorithms),
					OCSPStaple:                   cert.OCSPStaple,
					SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
					Leaf:                         cert.Leaf,
				},
			)
		}

		if config.VerifyConnection != nil {
			c.VerifyConnection = func(state utls.ConnectionState) error { return config.VerifyConnection(tlsstate.FromUTLS(state)) }
		}

		if config.EncryptedClientHelloRejectionVerify != nil {
			c.EncryptedClientHelloRejectionVerify = func(state utls.ConnectionState) error {
				return config.EncryptedClientHelloRejectionVerify(tlsstate.FromUTLS(state))
			}
		}

		conn := utls.UQUICClient(&utls.QUICConfig{TLSConfig: c, EnableSessionEvents: true}, utls.HelloCustom)
		if err := conn.ApplyPreset(&template); err != nil {
			conn.Close()
			return nil, fmt.Errorf("QUIC ClientHello: %w", err)
		}

		return &client{conn: conn}, nil
	}
}

func signatureSchemes(in []tls.SignatureScheme) []utls.SignatureScheme {
	out := make([]utls.SignatureScheme, len(in))
	for i, v := range in {
		out[i] = utls.SignatureScheme(v)
	}

	return out
}

type client struct {
	conn     *utls.UQUICConn
	session  *tls.SessionState
	original *utls.SessionState
}

func (c *client) syncSession() {
	if c.original != nil {
		c.original.Extra = c.session.Extra
		c.original.EarlyData = c.session.EarlyData
		c.original = nil
		c.session = nil
	}
}
func (c *client) Start(ctx context.Context) error { return convertError(c.conn.Start(ctx)) }

func (c *client) NextEvent() tls.QUICEvent {
	c.syncSession()
	event := c.conn.NextEvent()

	out := tls.QUICEvent{
		Kind:  tls.QUICEventKind(event.Kind),
		Level: tls.QUICEncryptionLevel(event.Level),
		Data:  event.Data,
		Suite: event.Suite,
		Err:   convertError(event.Err),
	}

	if event.SessionState != nil {
		c.original = event.SessionState
		c.session = &tls.SessionState{Extra: event.SessionState.Extra, EarlyData: event.SessionState.EarlyData}
		out.SessionState = c.session
	}

	return out
}

func (c *client) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	c.syncSession()
	return convertError(c.conn.HandleData(utls.QUICEncryptionLevel(level), data))
}

func (c *client) SetTransportParameters(data []byte) { c.conn.SetTransportParameters(data) }

func (c *client) SendSessionTicket(tls.QUICSessionTicketOptions) error {
	return errors.New("QUIC TLS client cannot send session tickets")
}

func (c *client) StoreSession(state *tls.SessionState) error {
	if state == nil || state != c.session || c.original == nil {
		return errors.New("QUIC session must be stored before draining its next event")
	}

	original := c.original
	c.syncSession()

	return c.conn.StoreSession(original)
}

func (c *client) Close() error { return convertError(c.conn.Close()) }

func (c *client) ConnectionState() tls.ConnectionState {
	return tlsstate.FromUTLS(c.conn.ConnectionState())
}

// The standard-library state is an informational snapshot. Its private TLS
// exporter closure cannot be transferred through public APIs. This is the same
// limitation as Surf's existing uTLS snapshots; no unsafe layout casts are used.

func convertError(err error) error {
	if err == nil {
		return nil
	}

	if alert, ok := errors.AsType[utls.AlertError](err); ok {
		return errors.Join(err, tls.AlertError(alert))
	}

	return err
}
