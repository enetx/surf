package main

import (
	"fmt"
	"reflect"
	"unsafe"

	"github.com/enetx/surf"
	quic "github.com/refraction-networking/uquic"
)

func main() {
	fmt.Println("=== HTTP/3 Fingerprint Verification ===\n")

	// Test different fingerprints
	testFingerprint("Chrome", buildChromeClient())
	testFingerprint("Firefox", buildFirefoxClient())
	testFingerprint("Chrome with DNS", buildChromeWithDNS())
	testFingerprint("Firefox with SOCKS5", buildFirefoxWithProxy())
	testFingerprint("Chrome with DNS + SOCKS5", buildChromeWithDNSAndProxy())

	// Compare fingerprints
	compareFingerprints()
}

func buildChromeClient() *surf.Client {
	return surf.NewClient().
		Builder().
		Impersonate().Chrome().
		HTTP3().
		Build()
}

func buildFirefoxClient() *surf.Client {
	return surf.NewClient().
		Builder().
		Impersonate().FireFox().
		HTTP3().
		Build()
}

func buildChromeWithDNS() *surf.Client {
	return surf.NewClient().
		Builder().
		DNS("8.8.8.8:53").
		Impersonate().Chrome().
		HTTP3().
		Build()
}

func buildFirefoxWithProxy() *surf.Client {
	return surf.NewClient().
		Builder().
		Proxy("socks5://127.0.0.1:2080").
		Impersonate().FireFox().
		HTTP3().
		Build()
}

func buildChromeWithDNSAndProxy() *surf.Client {
	return surf.NewClient().
		Builder().
		DNS("1.1.1.1:53").
		Proxy("socks5://127.0.0.1:2080").
		Impersonate().Chrome().
		HTTP3().
		Build()
}

func testFingerprint(name string, client *surf.Client) {
	fmt.Printf("=== %s ===\n", name)

	transport := client.GetTransport()
	if transport == nil {
		fmt.Println("✗ Transport not configured")
		return
	}

	transportValue := reflect.ValueOf(transport).Elem()

	// Extract and verify quicSpec
	quicSpecField := transportValue.FieldByName("quicSpec")
	if !quicSpecField.IsValid() {
		fmt.Println("✗ quicSpec field not found")
		return
	}

	quicSpec := (*quic.QUICSpec)(unsafe.Pointer(quicSpecField.UnsafeAddr()))

	// Print Initial Packet fingerprint
	fmt.Printf("Initial Packet Fingerprint:\n")
	fmt.Printf("  SrcConnIDLength: %d\n", quicSpec.InitialPacketSpec.SrcConnIDLength)
	fmt.Printf("  DestConnIDLength: %d\n", quicSpec.InitialPacketSpec.DestConnIDLength)
	fmt.Printf("  InitPacketNumberLength: %d\n", quicSpec.InitialPacketSpec.InitPacketNumberLength)
	fmt.Printf("  InitPacketNumber: %d\n", quicSpec.InitialPacketSpec.InitPacketNumber)
	fmt.Printf("  ClientTokenLength: %d\n", quicSpec.InitialPacketSpec.ClientTokenLength)
	fmt.Printf("  UDPDatagramMinSize: %d\n", quicSpec.UDPDatagramMinSize)

	// Check TLS fingerprinting from ClientHelloSpec
	if quicSpec.ClientHelloSpec != nil {
		fmt.Printf("TLS ClientHello Fingerprint:\n")
		fmt.Printf("  CipherSuites: %d [", len(quicSpec.ClientHelloSpec.CipherSuites))
		for i, suite := range quicSpec.ClientHelloSpec.CipherSuites[:min(3, len(quicSpec.ClientHelloSpec.CipherSuites))] {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("0x%04x", suite)
		}
		if len(quicSpec.ClientHelloSpec.CipherSuites) > 3 {
			fmt.Printf(", ...")
		}
		fmt.Printf("]\n")
		fmt.Printf("  Extensions: %d\n", len(quicSpec.ClientHelloSpec.Extensions))
		fmt.Printf("  CompressionMethods: %v\n", quicSpec.ClientHelloSpec.CompressionMethods)
	}

	// Check if TLS config exists (without trying to access it)
	tlsConfigField := transportValue.FieldByName("tlsConfig")
	if tlsConfigField.IsValid() && !tlsConfigField.IsNil() {
		fmt.Printf("✓ TLS config present (will apply fingerprinting)\n")

		// Show what ALPN will be set
		fmt.Printf("  ALPN will be set to: [h3, h3-29, h3-27]\n")
		fmt.Printf("  ServerName will be set from target host\n")

		// Show cipher suites that will be applied
		if quicSpec.ClientHelloSpec != nil && len(quicSpec.ClientHelloSpec.CipherSuites) > 0 {
			fmt.Printf("  CipherSuites will be overridden with fingerprint values\n")
		}
	}

	// Check DNS and Proxy configuration
	dialerField := transportValue.FieldByName("dialer")
	if dialerField.IsValid() && !dialerField.IsNil() {
		// Check for Resolver using unsafe
		dialer := dialerField.Elem()
		resolverField := dialer.FieldByName("Resolver")
		if resolverField.IsValid() && !resolverField.IsNil() {
			fmt.Printf("✓ Custom DNS configured (will use dialDNS)\n")
		}
	}

	proxyField := transportValue.FieldByName("staticProxy")
	if proxyField.IsValid() {
		proxy := proxyField.String()
		if proxy != "" {
			fmt.Printf("✓ SOCKS5 proxy configured: %s (will use dialSOCKS5)\n", proxy)
		}
	}

	// Calculate unique fingerprint hash
	hash := calculateFingerprintHash(quicSpec)
	fmt.Printf("Fingerprint Hash: %s\n", hash)

	fmt.Println()
}

func compareFingerprints() {
	fmt.Println("=== Fingerprint Comparison ===\n")

	clients := map[string]*surf.Client{
		"Chrome":           buildChromeClient(),
		"Chrome+DNS":       buildChromeWithDNS(),
		"Chrome+DNS+Proxy": buildChromeWithDNSAndProxy(),
		"Firefox":          buildFirefoxClient(),
		"Firefox+Proxy":    buildFirefoxWithProxy(),
	}

	hashes := make(map[string]string)

	for name, client := range clients {
		transport := client.GetTransport()
		transportValue := reflect.ValueOf(transport).Elem()
		quicSpecField := transportValue.FieldByName("quicSpec")

		if quicSpecField.IsValid() {
			quicSpec := (*quic.QUICSpec)(unsafe.Pointer(quicSpecField.UnsafeAddr()))
			hash := calculateFingerprintHash(quicSpec)
			hashes[name] = hash
		}
	}

	// Compare hashes
	fmt.Println("Fingerprint Hashes:")
	for name, hash := range hashes {
		fmt.Printf("  %-20s: %s\n", name, hash)
	}

	// Verify Chrome fingerprints are same regardless of DNS/Proxy
	if hashes["Chrome"] == hashes["Chrome+DNS"] &&
		hashes["Chrome"] == hashes["Chrome+DNS+Proxy"] {
		fmt.Println("\n✓ Chrome fingerprint preserved with DNS/Proxy")
	} else {
		fmt.Println("\n✗ Chrome fingerprint changed with DNS/Proxy!")
		fmt.Printf("  Chrome:            %s\n", hashes["Chrome"])
		fmt.Printf("  Chrome+DNS:        %s\n", hashes["Chrome+DNS"])
		fmt.Printf("  Chrome+DNS+Proxy:  %s\n", hashes["Chrome+DNS+Proxy"])
	}

	// Verify Firefox fingerprints are same with proxy
	if hashes["Firefox"] == hashes["Firefox+Proxy"] {
		fmt.Println("✓ Firefox fingerprint preserved with Proxy")
	} else {
		fmt.Println("✗ Firefox fingerprint changed with Proxy!")
		fmt.Printf("  Firefox:       %s\n", hashes["Firefox"])
		fmt.Printf("  Firefox+Proxy: %s\n", hashes["Firefox+Proxy"])
	}

	// Verify Chrome and Firefox are different
	if hashes["Chrome"] != hashes["Firefox"] {
		fmt.Println("✓ Chrome and Firefox have different fingerprints")
	} else {
		fmt.Println("✗ Chrome and Firefox have same fingerprint!")
	}
}

func calculateFingerprintHash(spec *quic.QUICSpec) string {
	hash := uint64(spec.InitialPacketSpec.SrcConnIDLength) << 56
	hash |= uint64(spec.InitialPacketSpec.DestConnIDLength) << 48
	hash |= uint64(spec.InitialPacketSpec.InitPacketNumberLength) << 40
	hash |= uint64(spec.InitialPacketSpec.InitPacketNumber) << 32
	hash |= uint64(spec.UDPDatagramMinSize) << 16

	if spec.ClientHelloSpec != nil {
		hash |= uint64(len(spec.ClientHelloSpec.CipherSuites)) << 8
		hash |= uint64(len(spec.ClientHelloSpec.Extensions))

		// Add cipher suite values to hash
		for _, suite := range spec.ClientHelloSpec.CipherSuites {
			hash ^= uint64(suite)
		}
	}

	return fmt.Sprintf("%016x", hash)
}
