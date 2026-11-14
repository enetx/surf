package chrome_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/profiles/chrome/common"
	"github.com/stretchr/testify/require"
)

func TestChromeIntermediateElisionCandidates(t *testing.T) {
	var manifest struct {
		ChromiumVersion string `json:"chromium_version"`
		SelectedSHA256  string `json:"selected_pem_sha256"`
		Certificates    []struct {
			SHA256 string `json:"sha256"`
			ID     string `json:"trust_anchor_id"`
		} `json:"certificates"`
	}
	data, err := os.ReadFile("../../../profiles/chrome/common/intermediates.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, "158.0.8127.18", manifest.ChromiumVersion)
	data, err = os.ReadFile("../../../profiles/chrome/common/intermediates.pem")
	require.NoError(t, err)
	selected := sha256.Sum256(data)
	require.Equal(t, manifest.SelectedSHA256, hex.EncodeToString(selected[:]))
	anchors := make(map[string]bool)
	for _, id := range trustAnchorsExtension(&chrome.HelloChrome_158).TrustAnchorIDs {
		anchors[hex.EncodeToString(id)] = true
	}

	pool := common.CertificateIntermediates()
	require.Len(t, pool.Subjects(), len(manifest.Certificates))
	for _, record := range manifest.Certificates {
		block, rest := pem.Decode(data)
		require.NotNil(t, block)
		require.Equal(t, "CERTIFICATE", block.Type)
		sum := sha256.Sum256(block.Bytes)
		require.Equal(t, record.SHA256, hex.EncodeToString(sum[:]))
		require.True(t, anchors[record.ID], "candidate ID absent from ClientHello: %s", record.ID)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		require.True(t, cert.IsCA)
		require.Error(t, cert.CheckSignatureFrom(cert), "candidate must not be a self-signed root")
		data = rest
	}
	require.Empty(t, data)

	rootPEM, err := os.ReadFile("../../testdata/tls_intermediates/gts-root-r4.pem")
	require.NoError(t, err)
	root, _ := pem.Decode(rootPEM)
	require.NotNil(t, root)
	cert, err := x509.ParseCertificate(root.Bytes)
	require.NoError(t, err)
	pool.AddCert(cert)
	require.Len(t, common.CertificateIntermediates().Subjects(), len(manifest.Certificates),
		"profile factory must not share mutable pools")
	require.NotNil(t, chrome.Desktop.CertificateIntermediates)
	require.NotNil(t, chrome.Mobile.CertificateIntermediates)
	require.Nil(t, chrome.IOS.CertificateIntermediates)
}

func TestChrome158NativeLinuxTrustAnchorExtension(t *testing.T) {
	var proof struct {
		Native struct {
			Body string `json:"body_hex"`
		} `json:"native"`
		Surf struct {
			Body string `json:"body_hex"`
		} `json:"surf"`
	}
	data, err := os.ReadFile("../../testdata/wire/linux_load/trust-anchor-extension.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &proof))
	require.Equal(t, chromeTrustAnchors, proof.Native.Body)
	require.Equal(t, proof.Native.Body, proof.Surf.Body)
}

func TestChromeGoogleStorageElidedChain(t *testing.T) {
	load := func(name string) *x509.Certificate {
		data, err := os.ReadFile("../../testdata/tls_intermediates/" + name)
		require.NoError(t, err)
		block, rest := pem.Decode(data)
		require.NotNil(t, block)
		require.Empty(t, rest)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		return cert
	}
	leaf := load("storage-googleapis-com.pem")
	root := load("gts-root-r4.pem")
	rootSum := sha256.Sum256(root.Raw)
	require.Equal(t, "349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d", hex.EncodeToString(rootSum[:]))
	roots := x509.NewCertPool()
	roots.AddCert(root)
	opts := x509.VerifyOptions{
		Roots: roots, DNSName: "storage.googleapis.com",
		CurrentTime: time.Date(2026, 11, 14, 7, 0, 0, 0, time.UTC),
	}
	_, err := leaf.Verify(opts)
	require.Error(t, err, "peer omitted WE2")
	opts.Intermediates = common.CertificateIntermediates()
	chains, err := leaf.Verify(opts)
	require.NoError(t, err)
	require.Len(t, chains, 1)
	require.Len(t, chains[0], 3)
	require.Equal(t, "WE2", chains[0][1].Subject.CommonName)
	opts.Roots = x509.NewCertPool()
	_, err = leaf.Verify(opts)
	require.Error(t, err, "bundled issuer candidates must never supply trust")
}
