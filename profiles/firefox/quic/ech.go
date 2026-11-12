package quic

import (
	"crypto/tls"

	"github.com/enetx/surf/profiles/firefox/internal/ech"
	utls "github.com/enetx/utls"
)

// NSS estimates a compressed ClientHelloInner, pads the name to 100 bytes and
// rounds the inner to 32 bytes before adding the AEAD tag. IP literals omit SNI.
// Prepare the cold size before uTLS measures extensions. On resumption, update
// it when the public PSK initialization callback supplies the actual ticket size.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13ech.c
type echPreSharedKey struct {
	*utls.UtlsPreSharedKeyExtension
	ech         *utls.GREASEEncryptedClientHelloExtension
	innerLength int
	early       *utls.EarlyDataExtension
}

func (e *echPreSharedKey) PrepareClientHello(spec *utls.ClientHelloSpec, config *tls.Config) {
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SNIExtension:
			extension.ServerName = config.ServerName
		case *utls.GREASEEncryptedClientHelloExtension:
			e.ech = extension
		case *utls.EarlyDataExtension:
			e.early = extension
		}
	}

	e.innerLength = ech.InnerLength(spec.CipherSuites, spec.CompressionMethods, spec.Extensions)
	ech.SetPayloadLength(e.ech, e.innerLength)
}

func (e *echPreSharedKey) InitializeByUtls(
	session *utls.SessionState,
	secret, binderKey []byte,
	identities []utls.PskIdentity,
) {
	e.UtlsPreSharedKeyExtension.InitializeByUtls(session, secret, binderKey, identities)
	length := e.innerLength + e.UtlsPreSharedKeyExtension.Len()

	if e.early != nil && e.early.Len() > 0 {
		length += 2 // The newly enabled inner early_data outer reference.
	}

	ech.SetPayloadLength(e.ech, length)
}
