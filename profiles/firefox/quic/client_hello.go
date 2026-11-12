package quic

import (
	"github.com/enetx/surf/profiles/firefox/desktop"
	utls "github.com/enetx/utls"
)

// NewClientHelloSpec follows the independently captured Firefox 160 QUIC
// handshake. NSS permutes built-in senders, then appends Neqo's custom QUIC
// parameters and ECH. PSK remains last when its binder is written. early_data
// belongs to the permuted built-ins, including when enabled on resumption.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/ssl3ext.c
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/ssl3con.c
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13ech.c
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13con.c
func NewClientHelloSpec() (utls.ClientHelloSpec, error) {
	spec := desktop.NewClientHelloSpec()

	spec.TLSVersMin = utls.VersionTLS13
	spec.TLSVersMax = utls.VersionTLS13

	spec.CipherSuites = []uint16{
		utls.TLS_AES_128_GCM_SHA256,
		utls.TLS_CHACHA20_POLY1305_SHA256,
		utls.TLS_AES_256_GCM_SHA384,
	}

	extensions := make([]utls.TLSExtension, 0, 16)

	var psk *utls.UtlsPreSharedKeyExtension
	var ech *utls.GREASEEncryptedClientHelloExtension

	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case *utls.SNIExtension,
			*utls.PSKKeyExchangeModesExtension,
			*utls.KeyShareExtension,
			*utls.ExtendedMasterSecretExtension,
			*utls.RenegotiationInfoExtension,
			*utls.StatusRequestExtension:
		case *utls.GREASEEncryptedClientHelloExtension:
			ech = e
			continue
		case *utls.UtlsPreSharedKeyExtension:
			psk = e
			continue
		case *utls.SupportedCurvesExtension:
			e.Curves = []utls.CurveID{utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521}
		case *utls.SignatureAlgorithmsExtension:
			e.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.ECDSAWithSHA1,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}
		case *utls.SupportedVersionsExtension:
			e.Versions = []uint16{utls.VersionTLS13}
		case *utls.ALPNExtension:
			e.AlpnProtocols = []string{"h3"}
		case *utls.FakeRecordSizeLimitExtension:
			e.Limit = 16385
		case *utls.UtlsCompressCertExtension:
			e.Algorithms = []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
				utls.CertCompressionZstd,
				utls.CertCompressionBrotli,
			}
		case *utls.FakeDelegatedCredentialsExtension:
			e.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.ECDSAWithSHA1,
			}
		default:
			continue
		}

		extensions = append(extensions, extension)
	}

	extensions = append(extensions, &utls.EarlyDataExtension{})
	extensions = utls.ShuffleChromeTLSExtensions(extensions)
	extensions = append(extensions, &utls.QUICTransportParametersExtension{})
	if ech != nil {
		extensions = append(extensions, ech)
	}
	if psk != nil {
		extensions = append(extensions, &echPreSharedKey{UtlsPreSharedKeyExtension: psk})
	}

	spec.Extensions = extensions

	return spec, nil
}
