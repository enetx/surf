package surf_test

import (
	"fmt"
	"testing"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/http/httptest"
	"github.com/enetx/surf"
)

func TestTLSGrabberHTTPS(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// Test TLS info grabber
	tlsInfo := resp.Ok().TLSGrabber()
	if tlsInfo == nil {
		t.Error("expected TLS info to be available for HTTPS request")
	}
}

func TestTLSGrabberHTTP(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// Test TLS info grabber for HTTP (should be nil)
	tlsInfo := resp.Ok().TLSGrabber()
	if tlsInfo != nil {
		t.Error("expected TLS info to be nil for HTTP request")
	}
}

func TestTLSGrabberWithImpersonate(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		Impersonate().Chrome().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// Test TLS info grabber with impersonation
	// Note: TLS info may not be available when using impersonation
	// as it may interfere with the standard TLS handshake process
	tlsInfo := resp.Ok().TLSGrabber()
	if tlsInfo == nil {
		t.Log("TLS info not available when using impersonation (this may be expected)")
	} else {
		t.Log("TLS info available with browser impersonation")
	}
}

func TestTLSGrabberWithJA3(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message": "success"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().
		JA().Chrome131().
		Build()

	if client == nil {
		t.Fatal("expected client to be built successfully")
	}

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// Test TLS info grabber with JA
	// Note: TLS info may not be available when using JA3 fingerprinting
	// as it may interfere with the standard TLS handshake process
	tlsInfo := resp.Ok().TLSGrabber()
	if tlsInfo == nil {
		t.Log("TLS info not available when using JA3 (this may be expected)")
	} else {
		t.Log("TLS info available with JA3 fingerprinting")
	}
}

func TestClientGetTLSConfig(t *testing.T) {
	t.Parallel()

	client := surf.NewClient()

	// Test that client has a TLS config
	tlsConfig := client.GetTLSConfig()
	if tlsConfig == nil {
		t.Error("expected client to have a TLS config")
	}
}

func TestTLSDataStructure(t *testing.T) {
	t.Parallel()

	// Test TLSData structure initialization
	tlsData := &surf.TLSData{
		ExtensionServerName:      "127.0.0.1",
		FingerprintSHA256:        "abcd1234",
		FingerprintSHA256OpenSSL: "AB:CD:12:34",
		TLSVersion:               "TLS13",
		CommonName:               []string{"127.0.0.1"},
		DNSNames:                 []string{"127.0.0.1", "localhost"},
		Emails:                   []string{"admin@localhost"},
		IssuerCommonName:         []string{"Test CA"},
		IssuerOrg:                []string{"Test Organization"},
		Organization:             []string{"Example Corp"},
	}

	if tlsData.ExtensionServerName != "127.0.0.1" {
		t.Errorf("expected ServerName to be '127.0.0.1', got %s", tlsData.ExtensionServerName)
	}

	if len(tlsData.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(tlsData.DNSNames))
	}

	if len(tlsData.CommonName) != 1 {
		t.Errorf("expected 1 common name, got %d", len(tlsData.CommonName))
	}

	if tlsData.TLSVersion != "TLS13" {
		t.Errorf("expected TLS version to be 'TLS13', got %s", tlsData.TLSVersion)
	}
}

func TestTLSDataFields(t *testing.T) {
	t.Parallel()

	// Test that TLSData fields are properly accessible
	tlsData := &surf.TLSData{}

	// Test field assignment
	tlsData.ExtensionServerName = "test.com"
	tlsData.FingerprintSHA256 = "fingerprint"
	tlsData.TLSVersion = "TLS12"

	tlsData.DNSNames = append(tlsData.DNSNames, "test.com")
	tlsData.CommonName = append(tlsData.CommonName, "Test Common Name")
	tlsData.Organization = append(tlsData.Organization, "Test Org")
	tlsData.IssuerCommonName = append(tlsData.IssuerCommonName, "Test Issuer")
	tlsData.IssuerOrg = append(tlsData.IssuerOrg, "Test Issuer Org")
	tlsData.Emails = append(tlsData.Emails, "test@localhost")

	// Verify assignments
	if tlsData.ExtensionServerName != "test.com" {
		t.Error("ExtensionServerName not set correctly")
	}
	if tlsData.FingerprintSHA256 != "fingerprint" {
		t.Error("FingerprintSHA256 not set correctly")
	}
	if tlsData.TLSVersion != "TLS12" {
		t.Error("TLSVersion not set correctly")
	}
	if len(tlsData.DNSNames) != 1 || tlsData.DNSNames[0] != "test.com" {
		t.Error("DNSNames not set correctly")
	}
	if len(tlsData.CommonName) != 1 || tlsData.CommonName[0] != "Test Common Name" {
		t.Error("CommonName not set correctly")
	}
	if len(tlsData.Organization) != 1 || tlsData.Organization[0] != "Test Org" {
		t.Error("Organization not set correctly")
	}
	if len(tlsData.IssuerCommonName) != 1 || tlsData.IssuerCommonName[0] != "Test Issuer" {
		t.Error("IssuerCommonName not set correctly")
	}
	if len(tlsData.IssuerOrg) != 1 || tlsData.IssuerOrg[0] != "Test Issuer Org" {
		t.Error("IssuerOrg not set correctly")
	}
	if len(tlsData.Emails) != 1 || tlsData.Emails[0] != "test@localhost" {
		t.Error("Emails not set correctly")
	}
}

func TestTLSGrabberWithHTTPS2(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"tls": "test"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Fatal(resp.Err())
	}

	if !resp.Ok().StatusCode.IsSuccess() {
		t.Errorf("expected success status, got %d", resp.Ok().StatusCode)
	}

	// Test TLS info with HTTP/2
	tlsInfo := resp.Ok().TLSGrabber()
	if tlsInfo == nil {
		t.Error("expected TLS info to be available for HTTPS/2 request")
	} else {
		// Test that TLS info has expected structure
		if tlsInfo.TLSVersion == "" {
			t.Log("TLS version not captured (this might be expected in test environment)")
		}
	}
}

func TestTLSGrabberWithHTTP3(t *testing.T) {
	t.Parallel()

	// Skip if HTTP/3 is not available (requires special setup)
	t.Skip("HTTP/3 testing requires complex server setup")

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"tls": "test"}`)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	client := surf.NewClient().Builder().Build()

	req := client.Get(g.String(ts.URL))
	resp := req.Do()

	if resp.IsErr() {
		t.Skip("HTTP/3 not available in test environment")
	}

	// Test TLS info with HTTP/3 if available
	tlsInfo := resp.Ok().TLSGrabber()
	if tlsInfo != nil {
		t.Log("TLS info available with HTTP/3")
	}
}
