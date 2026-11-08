package quic

import (
	"slices"

	utls "github.com/refraction-networking/utls"
)

// NewClientHelloSpec follows the independently captured Chromium 156 QUIC
// handshake. It is separate from the browser's TCP template. uTLS generates the
// key material, GREASE ECH payload and PSK binders; Surf owns the advertised fields.
func NewClientHelloSpec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_155)
	if err != nil {
		return utls.ClientHelloSpec{}, err
	}

	spec.TLSVersMin = utls.VersionTLS13
	spec.TLSVersMax = utls.VersionTLS13

	spec.CipherSuites = []uint16{
		utls.TLS_AES_128_GCM_SHA256,
		utls.TLS_AES_256_GCM_SHA384,
		utls.TLS_CHACHA20_POLY1305_SHA256,
	}

	extensions := make([]utls.TLSExtension, 0, 13)

	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case *utls.SNIExtension,
			*utls.TrustAnchorsExtension,
			*utls.GREASEEncryptedClientHelloExtension,
			*utls.PSKKeyExchangeModesExtension,
			*utls.UtlsCompressCertExtension:
		case *utls.SignatureAlgorithmsExtension:
			e.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}
		case *utls.SupportedCurvesExtension:
			e.Curves = []utls.CurveID{utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384}
		case *utls.KeyShareExtension:
			e.KeyShares = slices.DeleteFunc(
				e.KeyShares,
				func(share utls.KeyShare) bool {
					return share.Group != utls.X25519MLKEM768 && share.Group != utls.X25519
				},
			)
		case *utls.SupportedVersionsExtension:
			e.Versions = []uint16{utls.VersionTLS13}
		case *utls.ALPNExtension:
			e.AlpnProtocols = []string{"h3"}
		case *utls.ApplicationSettingsExtensionNew:
			e.SupportedProtocols = []string{"h3"}
		default:
			continue
		}

		extensions = append(extensions, extension)
	}

	// Extension order is independently randomized for each connection.
	extensions = append(extensions, &utls.QUICTransportParametersExtension{}, &utls.UtlsPreSharedKeyExtension{})

	spec.Extensions = utls.ShuffleChromeTLSExtensions(extensions)

	return spec, nil
}
