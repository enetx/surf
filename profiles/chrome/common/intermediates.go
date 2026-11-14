package common

import (
	"crypto/x509"
	_ "embed"
)

// Chromium's extra, constrained intermediates corresponding to the advertised
// Trust Anchor IDs. The signed certificates remain untrusted issuer candidates.
// https://github.com/chromium/chromium/blob/158.0.8127.18/net/data/ssl/chrome_root_store/root_store.textproto
// https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-05.html#name-intermediate-elision
//
//go:embed intermediates.pem
var certificateIntermediatesPEM []byte

// CertificateIntermediates returns fresh Chrome 158 issuer candidates for
// intermediate elision. Verification still requires the application's roots
// and all ordinary hostname, validity and CA constraints.
func CertificateIntermediates() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificateIntermediatesPEM) {
		panic("surf: invalid built-in Chrome intermediate certificates")
	}

	return pool
}
