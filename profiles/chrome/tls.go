package chrome

import utls "github.com/refraction-networking/utls"

// ML-DSA (post-quantum) TLS 1.3 signature schemes that Chrome 152 advertises at the
// head of its signature_algorithms list. utls does not yet name them, so they are
// spelled as raw SignatureScheme code points (per the TLS ML-DSA draft). Without
// them a Chrome-152 UA ships a pre-152 JA4, which some Akamai deployments reject.
const (
	MLDSA44 utls.SignatureScheme = 0x0904
	MLDSA65 utls.SignatureScheme = 0x0905
	MLDSA87 utls.SignatureScheme = 0x0906
)

// extensionTrustAnchors is the TLS Trust Anchor Identifiers extension
// (draft-ietf-tls-trust-anchor-ids, code point 0xca34). Chrome 152 sends it on every
// ClientHello, so its presence is part of the Chrome 152 JA4 (t13d1517h2_…); a hello
// without it is a pre-152 fingerprint, which some Akamai deployments reject when the
// UA claims Chrome 152.
const extensionTrustAnchors uint16 = 0xca34

// chrome152TrustAnchorIDs is the extension body Chrome 152 sends: a length-prefixed
// TrustAnchorIdentifierList of the Chrome Root Store trust anchor IDs it advertises,
// captured verbatim from a Google Chrome 152.0.7977 desktop ClientHello.
//
// The order matters and is not randomised. Chromium walks the compiled-in kChromeRootCertList
// in array order (net/cert/internal/trust_store_chrome.cc), passes the bytes to
// SSL_set1_requested_trust_anchors untouched, and BoringSSL writes them into the extension
// verbatim — nothing shuffles the list the way the extension order is shuffled. So the order
// is a compile-time constant of one Chrome build: stable across connections and hosts, but two
// builds carrying different root store snapshots emit different orders for the same set of IDs.
// These bytes must therefore come from a Google Chrome release, matching the branding the
// profile claims in sec-ch-ua; a Chromium or ungoogled-chromium build of the same major
// version is not interchangeable here.
var chrome152TrustAnchorIDs = []byte{
	0x00, 0xcc,
	0x04, 0xd6, 0x79, 0x09, 0x06,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07,
	0x04, 0xd6, 0x79, 0x09, 0x0c,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x06,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x13,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d,
	0x04, 0xd6, 0x79, 0x09, 0x01,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x0d,
	0x04, 0xd6, 0x79, 0x09, 0x0d,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x0f,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x12,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09,
	0x04, 0xd6, 0x79, 0x09, 0x02,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x01,
	0x04, 0xd6, 0x79, 0x09, 0x0e,
	0x04, 0xd6, 0x79, 0x09, 0x09,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a,
	0x04, 0xd6, 0x79, 0x09, 0x03,
	0x04, 0xd6, 0x79, 0x09, 0x0f,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b,
	0x04, 0xd6, 0x79, 0x09, 0x04,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x14,
	0x04, 0xd6, 0x79, 0x09, 0x0a,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12,
	0x04, 0xd6, 0x79, 0x09, 0x07,
	0x04, 0xd6, 0x79, 0x09, 0x08,
	0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c,
	0x04, 0xd6, 0x79, 0x09, 0x05,
	0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e,
	0x04, 0xd6, 0x79, 0x09, 0x0b,
}

// HelloChrome_152 mirrors HelloChrome_150 (ML-DSA signature schemes at the head of
// signature_algorithms) and adds what Chrome 152 sends on top: a GREASE signature scheme
// and the trust_anchors extension. Together with the per-connection extension shuffle
// (Variant.ShuffleExtensions / JA.Chrome152) this reproduces a Chrome 152 desktop
// ClientHello structurally, not just its JA4.
//
// The extension order declared below is Chrome's own order. It is never shuffled in place:
// the shuffle runs per connection on a private clone at dial time, so this value stays a
// stable reference point across runs.
var HelloChrome_152 = utls.ClientHelloSpec{
	CipherSuites: []uint16{
		utls.GREASE_PLACEHOLDER,
		utls.TLS_AES_128_GCM_SHA256,
		utls.TLS_AES_256_GCM_SHA384,
		utls.TLS_CHACHA20_POLY1305_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	CompressionMethods: []byte{0x00},
	Extensions: []utls.TLSExtension{
		&utls.UtlsGREASEExtension{},
		&utls.SNIExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		},
		&utls.SupportedCurvesExtension{
			Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			},
		},
		&utls.SupportedPointsExtension{
			SupportedPoints: []byte{0x00},
		},
		&utls.SessionTicketExtension{},
		&utls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		&utls.StatusRequestExtension{},
		&utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				// Chrome 152 GREASEs signature_algorithms; surf substitutes the
				// placeholder with a random GREASE value per connection (see JA.getSpec).
				utls.GREASE_PLACEHOLDER,
				MLDSA44,
				MLDSA65,
				MLDSA87,
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			},
		},
		&utls.SCTExtension{},
		&utls.KeyShareExtension{
			KeyShares: []utls.KeyShare{
				{Group: utls.GREASE_PLACEHOLDER, Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			},
		},
		&utls.PSKKeyExchangeModesExtension{
			Modes: []uint8{
				utls.PskModeDHE,
			},
		},
		&utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			},
		},
		&utls.UtlsCompressCertExtension{
			Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			},
		},
		&utls.ApplicationSettingsExtensionNew{
			SupportedProtocols: []string{"h2"},
		},
		&utls.GenericExtension{Id: extensionTrustAnchors, Data: chrome152TrustAnchorIDs},
		utls.BoringGREASEECH(),
		&utls.UtlsGREASEExtension{},
		&utls.UtlsPreSharedKeyExtension{},
	},
}

// HelloChrome_152_Mobile is a placeholder mobile variant. On the day real Chrome Android 152
// ClientHello bytes are observed, replace this body — it is the single point of substitution
// for the mobile TLS fingerprint.
var HelloChrome_152_Mobile = HelloChrome_152
