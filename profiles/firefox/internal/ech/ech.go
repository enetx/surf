package ech

import utls "github.com/enetx/utls"

// InnerLength estimates Firefox's compressed ClientHelloInner before padding.
// Ordinary TLS 1.3 extensions become two-byte references; SNI and versions stay
// inline. Firefox pads the server name to 100 bytes, then the inner to 32 bytes.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13ech.c
func InnerLength(ciphers []uint16, compression []uint8, extensions []utls.TLSExtension) int {
	length := 2 + 32 + 1 + 2 + 2*len(ciphers) + 1 + len(compression) + 2
	length += 5 // Inner ECH extension: header plus the inner/outer byte.
	namePadding, compressed := 100, 0

	for _, extension := range extensions {
		switch extension := extension.(type) {
		case *utls.SNIExtension:
			length += extension.Len()
			namePadding = max(100-len(extension.ServerName), 0)
		case *utls.SupportedVersionsExtension:
			length += 7 // Extension header, vector length and TLS 1.3.
		case *utls.ExtendedMasterSecretExtension, *utls.RenegotiationInfoExtension,
			*utls.SupportedPointsExtension, utls.ISessionTicketExtension:
			// TLS 1.2-only extensions are absent from the inner hello.
		case utls.PreSharedKeyExtension, *utls.GREASEEncryptedClientHelloExtension:
			// PSK is added after the session loads; inner ECH is counted above.
		default:
			compressed++
		}
	}

	if compressed > 0 {
		length += 5 + 2*compressed // outer_extensions header and references.
	}

	return length + namePadding
}

// SetPayloadLength replaces a preliminary GREASE payload when session loading
// changes the inner size. Subsequent marshals and HelloRetryRequest reuse it.
func SetPayloadLength(ech *utls.GREASEEncryptedClientHelloExtension, innerLength int) {
	if ech == nil {
		return
	}

	length := uint16((innerLength + 31) &^ 31)

	if len(ech.CandidatePayloadLens) == 1 && ech.CandidatePayloadLens[0] == length {
		return
	}

	*ech = utls.GREASEEncryptedClientHelloExtension{
		CandidateCipherSuites: ech.CandidateCipherSuites,
		CandidateConfigIds:    ech.CandidateConfigIds,
		EncapsulatedKey:       ech.EncapsulatedKey,
		CandidatePayloadLens:  []uint16{length},
	}
}
