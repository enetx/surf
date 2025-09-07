package main

import (
	"crypto/rand"
	"encoding/binary"
	"log"

	"github.com/enetx/g"
	"github.com/enetx/http2"
	"github.com/enetx/surf"
	"github.com/enetx/surf/header"
	tls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
)

// "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
// "ja3_hash": "9a7f6a45c84d90c9e8baecb0c9ae8dff",
// "ja4": "t13d1515h2_8daaf6152771_2764158f9823",
// "ja4_r": "t13d1515h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0000,0005,000a,000b,000d,0017,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
// "akamai": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
// "akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
// "peetprint": "772-771|2-1.1|29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|1||4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53|0-10-11-13-16-23-28-34-35-43-45-5-51-65037-65281",
// "peetprint_hash": "2eb215311454f1bcef8d33d5281a880d"
var spec = tls.ClientHelloSpec{
	TLSVersMin: tls.VersionTLS12,
	TLSVersMax: tls.VersionTLS13,

	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},

	CompressionMethods: []uint8{0x00}, // null

	Extensions: []tls.TLSExtension{
		// 0: server_name
		&tls.SNIExtension{},

		// 23: extended_master_secret
		&tls.ExtendedMasterSecretExtension{},

		// 65281: renegotiation_info (boringssl)
		&tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},

		// 10: supported_groups
		&tls.SupportedCurvesExtension{
			Curves: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
				256, // ffdhe2048
				257, // ffdhe3072
			},
		},

		// 11: ec_point_formats
		&tls.SupportedPointsExtension{
			SupportedPoints: []uint8{0x00}, // uncompressed
		},

		// 35: session_ticket (empty)
		&tls.SessionTicketExtension{},

		// 16: ALPN
		&tls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},

		// 5: status_request (OCSP)
		&tls.StatusRequestExtension{},

		// 34: delegated_credentials (boringssl)
		&tls.FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.ECDSAWithSHA1,
			},
		},

		// 51: key_share (X25519, P-256)
		&tls.KeyShareExtension{
			KeyShares: []tls.KeyShare{
				{Group: tls.X25519},
				{Group: tls.CurveP256},
			},
		},

		// 43: supported_versions (TLS 1.3, 1.2)
		&tls.SupportedVersionsExtension{
			Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		},

		// 13: signature_algorithms
		&tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
		},

		// 45: psk_key_exchange_modes = psk_dhe_ke (1)
		&tls.PSKKeyExchangeModesExtension{
			Modes: []uint8{tls.PskModeDHE},
		},

		// 28: record_size_limit = 0x4001
		&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},

		// 65037: EncryptedClientHello (boringssl GREASE)
		&tls.GREASEEncryptedClientHelloExtension{
			CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
				{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
				{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
			},
			// payload length = 0x01EC (492)
			CandidatePayloadLens: []uint16{492},
		},
	},
}

// "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-65037,29-23-24-25-256-257,0",
// "ja3_hash": "0faf2a91198d40dbd58b9308f3fca2fd",
// "ja4": "t13d1513h2_8daaf6152771_b10d063d83a8",
// "ja4_r": "t13d1513h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0000,0005,000a,000b,000d,0017,001c,0022,002b,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
// "akamai": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
// "akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
// "peetprint": "772-771|2-1.1|29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|0||4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53|0-10-11-13-16-23-28-34-43-5-51-65037-65281",
// "peetprint_hash": "3838f472ba00b12aab5a866552abf7a4"
var specPrivate = tls.ClientHelloSpec{
	TLSVersMin: tls.VersionTLS12,
	TLSVersMax: tls.VersionTLS13,

	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},

	CompressionMethods: []uint8{0x00}, // null

	Extensions: []tls.TLSExtension{
		// 0: server_name
		&tls.SNIExtension{},

		// 23: extended_master_secret
		&tls.ExtendedMasterSecretExtension{},

		// 65281: renegotiation_info (boringssl)
		&tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},

		// 10: supported_groups
		&tls.SupportedCurvesExtension{
			Curves: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
				256, // ffdhe2048
				257, // ffdhe3072
			},
		},

		// 11: ec_point_formats
		&tls.SupportedPointsExtension{
			SupportedPoints: []uint8{0x00}, // uncompressed
		},

		// 16: ALPN
		&tls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},

		// 5: status_request (OCSP)
		&tls.StatusRequestExtension{},

		// 34: delegated_credentials (boringssl)
		&tls.FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.ECDSAWithSHA1,
			},
		},

		// 51: key_share (X25519, P-256)
		&tls.KeyShareExtension{
			KeyShares: []tls.KeyShare{
				{Group: tls.X25519},
				{Group: tls.CurveP256},
			},
		},

		// 43: supported_versions (TLS 1.3, 1.2)
		&tls.SupportedVersionsExtension{
			Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		},

		// 13: signature_algorithms
		&tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
		},

		// 28: record_size_limit = 0x4001
		&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},

		// 65037: EncryptedClientHello (boringssl GREASE)
		&tls.GREASEEncryptedClientHelloExtension{
			CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
				{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
				{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
			},
			CandidatePayloadLens: []uint16{223},
		},
	},
}

func main() {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":path", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	headers.Set(header.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.REFERER, "")
	headers.Set(header.UPGRADE_INSECURE_REQUESTS, "1")
	headers.Set(header.SEC_FETCH_DEST, "document")
	headers.Set(header.SEC_FETCH_MODE, "navigate")
	headers.Set(header.SEC_FETCH_SITE, "none")
	headers.Set(header.SEC_FETCH_USER, "?1")
	headers.Set(header.PRIORITY, "u=0, i")

	r := surf.NewClient().
		Builder().
		Boundary(func() g.String {
			prefix := g.String("---------------------------")

			var builder g.Builder
			builder.WriteString(prefix)

			for range 3 {
				var b [4]byte
				rand.Read(b[:])
				builder.WriteString(g.Int(binary.LittleEndian.Uint32(b[:])).String())
			}

			return builder.String()
		}).
		JA().
		// SetHelloSpec(spec).
		SetHelloSpec(specPrivate).
		HTTP2Settings().
		HeaderTableSize(65536).
		InitialWindowSize(131072).
		MaxFrameSize(16384).
		EnablePush(0).
		ConnectionFlow(12517377).
		PriorityParam(
			http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    41,
			}).
		Set().
		SetHeaders(headers).
		Build().
		Get("https://tls.peet.ws/api/clean").
		Do()

	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Body.String().Print()
}
