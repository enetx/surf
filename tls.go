package surf

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
)

// TLSData represents information about a TLS certificate.
type TLSData struct {
	CommonName               []string // List of common names associated with the certificate.
	DNSNames                 []string // List of DNS names associated with the certificate.
	Emails                   []string // List of email addresses associated with the certificate.
	IssuerCommonName         []string // List of common names of the certificate issuer.
	IssuerOrg                []string // List of organizations of the certificate issuer.
	Organization             []string // List of organizations associated with the certificate.
	ExtensionServerName      string   // Server name extension of the TLS certificate.
	FingerprintSHA256        string   // SHA-256 fingerprint of the certificate.
	FingerprintSHA256OpenSSL string   // SHA-256 fingerprint compatible with OpenSSL.
	TLSVersion               string   // TLS version used.
}

// tlsGrabber takes a TLS connection state and returns a tlsData struct containing information
// about the TLS connection.
func tlsGrabber(cs *tls.ConnectionState) *TLSData {
	var td TLSData

	if cs != nil && len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		td.DNSNames = append(td.DNSNames, cert.DNSNames...)
		td.Emails = append(td.Emails, cert.EmailAddresses...)
		td.CommonName = append(td.CommonName, cert.Subject.CommonName)
		td.Organization = append(td.Organization, cert.Subject.Organization...)
		td.IssuerOrg = append(td.IssuerOrg, cert.Issuer.Organization...)
		td.IssuerCommonName = append(td.IssuerCommonName, cert.Issuer.CommonName)
		td.ExtensionServerName = cs.ServerName

		tlsVersionStringMap := map[uint16]string{
			0x0300: "SSL30",
			0x0301: "TLS10",
			0x0302: "TLS11",
			0x0303: "TLS12",
			0x0304: "TLS13",
		}

		if version, ok := tlsVersionStringMap[cs.Version]; ok {
			td.TLSVersion = version
		}

		if fingerprintSHA256, err := calculateFingerprints(cs); err == nil {
			td.FingerprintSHA256 = hex.EncodeToString(fingerprintSHA256)
			td.FingerprintSHA256OpenSSL = openSSL(fingerprintSHA256)
		}
	}

	return &td
}

// calculateFingerprints takes a TLS connection state and returns the SHA256 fingerprint
// of the first certificate in the chain or an error if no certificates are found.
func calculateFingerprints(c *tls.ConnectionState) ([]byte, error) {
	if len(c.PeerCertificates) == 0 {
		err := errors.New("no certificates found")
		return nil, err
	}

	cert := c.PeerCertificates[0]
	dataSHA256 := sha256.Sum256(cert.Raw)
	fingerprintSHA256 := dataSHA256[:]

	return fingerprintSHA256, nil
}

// openSSL takes a byte slice of a fingerprint and returns a string representation in the OpenSSL
// format.
func openSSL(fpBytes []byte) string {
	var buf bytes.Buffer

	for i, f := range fpBytes {
		if i > 0 {
			_, _ = fmt.Fprintf(&buf, ":")
		}
		_, _ = fmt.Fprintf(&buf, "%02X", f)
	}

	return buf.String()
}
