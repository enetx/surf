package desktop

import (
	"slices"

	utls "github.com/refraction-networking/utls"
)

// NewClientHelloSpec derives the current Firefox 160 desktop handshake from
// uTLS's native Firefox profile, retaining its hybrid/classical key-share reuse.
func NewClientHelloSpec() utls.ClientHelloSpec {
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_148)
	if err != nil {
		panic("firefox profile: " + err.Error())
	}

	spec.CipherSuites = slices.DeleteFunc(spec.CipherSuites, func(cipher uint16) bool {
		return cipher == utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA ||
			cipher == utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	})

	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+3)
	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case *utls.SupportedCurvesExtension:
			e.Curves = slices.DeleteFunc(e.Curves, func(curve utls.CurveID) bool {
				return curve == 0x0100 || curve == 0x0101 // ffdhe2048, ffdhe3072
			})
		case *utls.GREASEEncryptedClientHelloExtension:
			// uTLS adds a 16-byte AEAD tag: the captured payload is 240 bytes.
			e.CandidatePayloadLens = []uint16{224}
		}

		extensions = append(extensions, extension)

		switch extension.(type) {
		case *utls.SupportedPointsExtension:
			extensions = append(extensions, &sessionTicketExtension{})
		case *utls.SignatureAlgorithmsExtension:
			extensions = append(extensions, &utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}})
		}
	}

	// Fresh connections omit an empty PSK; an enabled session cache can resume.
	spec.Extensions = append(extensions, &utls.UtlsPreSharedKeyExtension{})

	return spec
}
