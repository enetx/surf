package firefox

import (
	utls "github.com/enetx/utls"
	"github.com/enetx/utls/dicttls"
)

var HelloFirefox_147 = utls.ClientHelloSpec{
	TLSVersMin: utls.VersionTLS12,
	TLSVersMax: utls.VersionTLS13,
	CipherSuites: []uint16{
		utls.TLS_AES_128_GCM_SHA256,
		utls.TLS_CHACHA20_POLY1305_SHA256,
		utls.TLS_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	CompressionMethods: []uint8{
		0x0, // no compression
	},
	Extensions: []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		},
		&utls.SupportedCurvesExtension{
			Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				256,
				257,
			},
		},
		&utls.SupportedPointsExtension{
			SupportedPoints: []uint8{
				0x0, // uncompressed
			},
		},
		&utls.SessionTicketExtension{},
		&utls.ALPNExtension{
			AlpnProtocols: []string{
				"h2",
				"http/1.1",
			},
		},
		&utls.StatusRequestExtension{},
		&utls.DelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.ECDSAWithSHA1,
			},
		},
		&utls.SCTExtension{},
		&utls.KeyShareExtensionExtended{
			KeyShareExtension: &utls.KeyShareExtension{
				KeyShares: []utls.KeyShare{
					{
						Group: utls.X25519MLKEM768,
					},
					{
						Group: utls.X25519,
					},
					{
						Group: utls.CurveP256,
					},
				},
			},
			HybridReuseKey: true,
		},
		&utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			},
		},
		&utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			},
		},
		&utls.PSKKeyExchangeModesExtension{
			Modes: []uint8{
				utls.PskModeDHE,
			},
		},
		&utls.FakeRecordSizeLimitExtension{
			Limit: 0x4001,
		},
		&utls.UtlsCompressCertExtension{
			Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
				utls.CertCompressionBrotli,
				utls.CertCompressionZstd,
			},
		},
		&utls.GREASEEncryptedClientHelloExtension{
			CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
				{
					KdfId:  dicttls.HKDF_SHA256,
					AeadId: dicttls.AEAD_AES_128_GCM,
				},
				{
					KdfId:  dicttls.HKDF_SHA256,
					AeadId: dicttls.AEAD_CHACHA20_POLY1305,
				},
			},
			CandidatePayloadLens: []uint16{223}, // +16: 239
		},
		&utls.UtlsPreSharedKeyExtension{},
	},
}

var HelloFirefoxPrivate_147 = utls.ClientHelloSpec{
	TLSVersMin: utls.VersionTLS12,
	TLSVersMax: utls.VersionTLS13,
	CipherSuites: []uint16{
		utls.TLS_AES_128_GCM_SHA256,
		utls.TLS_CHACHA20_POLY1305_SHA256,
		utls.TLS_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	CompressionMethods: []uint8{
		0x0, // no compression
	},
	Extensions: []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		},
		&utls.SupportedCurvesExtension{
			Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				256,
				257,
			},
		},
		&utls.SupportedPointsExtension{
			SupportedPoints: []uint8{
				0x0, // uncompressed
			},
		},
		&utls.ALPNExtension{
			AlpnProtocols: []string{
				"h2",
				"http/1.1",
			},
		},
		&utls.StatusRequestExtension{},
		&utls.DelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.ECDSAWithSHA1,
			},
		},
		&utls.SCTExtension{},
		&utls.KeyShareExtensionExtended{
			KeyShareExtension: &utls.KeyShareExtension{
				KeyShares: []utls.KeyShare{
					{
						Group: utls.X25519MLKEM768,
					},
					{
						Group: utls.X25519,
					},
					{
						Group: utls.CurveP256,
					},
				},
			},
			HybridReuseKey: true,
		},
		&utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			},
		},
		&utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			},
		},
		&utls.FakeRecordSizeLimitExtension{
			Limit: 0x4001,
		},
		&utls.UtlsCompressCertExtension{
			Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
				utls.CertCompressionBrotli,
				utls.CertCompressionZstd,
			},
		},
		&utls.GREASEEncryptedClientHelloExtension{
			CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
				{
					KdfId:  dicttls.HKDF_SHA256,
					AeadId: dicttls.AEAD_AES_128_GCM,
				},
				{
					KdfId:  dicttls.HKDF_SHA256,
					AeadId: dicttls.AEAD_CHACHA20_POLY1305,
				},
			},
			CandidatePayloadLens: []uint16{223}, // +16: 239
		},
	},
}
