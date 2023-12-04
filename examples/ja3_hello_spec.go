package main

import (
	"fmt"

	tls "github.com/refraction-networking/utls"
	"gitlab.com/x0xO/surf"
)

func main() {
	type Ja3 struct {
		Ja3Hash string `json:"ja3_hash"`
		Ja3     string `json:"ja3"`
	}

	// https://tlsfingerprint.io/top
	spec := tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.StatusRequestExtension{},
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
				},
			},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA1,
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithSHA1,
				0x0202,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithP521AndSHA512,
			}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		},
	}

	opt := surf.NewOptions().JA3().SetHelloSpec(spec)

	r, err := surf.NewClient().SetOptions(opt).
		Get("https://tls.peet.ws/api/clean").
		Do()
	if err != nil {
		fmt.Println(err)
		return
	}

	var obj Ja3

	r.Body.JSON(&obj)

	fmt.Println(obj.Ja3Hash)
	fmt.Println(obj.Ja3)
}
