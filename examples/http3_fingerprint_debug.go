package main

import (
	"fmt"
	"reflect"
	"unsafe"

	"github.com/enetx/surf"
	quic "github.com/refraction-networking/uquic"
)

func main() {
	fmt.Println("=== HTTP/3 Fingerprint Debug Analysis ===")
	fmt.Println()

	// Test Chrome fingerprint
	chromeClient := surf.NewClient().
		Builder().
		Impersonate().
		Chrome().
		HTTP3().
		Build()

	inspectTransport("Chrome", chromeClient)

	// Test Firefox fingerprint
	firefoxClient := surf.NewClient().
		Builder().
		Impersonate().
		FireFox().
		HTTP3().
		Build()

	inspectTransport("Firefox", firefoxClient)

	// Test custom QUIC ID
	customClient := surf.NewClient().
		Builder().
		HTTP3Settings().
		SetQUICID(quic.QUICChrome_115).
		Set().
		Build()

	inspectTransport("Custom Chrome ID", customClient)
}

func inspectTransport(name string, client *surf.Client) {
	fmt.Printf("=== %s Transport Inspection ===\n", name)

	if client == nil {
		fmt.Printf("Client not created\n")
		return
	}

	// Check if transport is configured
	if client.GetTransport() == nil {
		fmt.Printf("Transport not configured\n")
		return
	}

	transport := client.GetTransport()
	fmt.Printf("Transport type: %T\n", transport)

	// Use reflection to inspect uquicTransport fields
	transportValue := reflect.ValueOf(transport)
	if transportValue.Kind() == reflect.Ptr {
		transportValue = transportValue.Elem()
	}

	if transportValue.Kind() == reflect.Struct {
		// Look for quicSpec field
		quicSpecField := transportValue.FieldByName("quicSpec")
		if quicSpecField.IsValid() {
			fmt.Printf("QUIC Spec found in transport\n")

			// Extract quicSpec using unsafe pointer
			quicSpec := (*quic.QUICSpec)(unsafe.Pointer(quicSpecField.UnsafeAddr()))

			fmt.Printf("Initial Packet Spec:\n")
			fmt.Printf(" - SrcConnIDLength: %d\n", quicSpec.InitialPacketSpec.SrcConnIDLength)
			fmt.Printf(" - DestConnIDLength: %d\n", quicSpec.InitialPacketSpec.DestConnIDLength)
			fmt.Printf(" - InitPacketNumberLength: %d\n", quicSpec.InitialPacketSpec.InitPacketNumberLength)
			fmt.Printf(" - InitPacketNumber: %d\n", quicSpec.InitialPacketSpec.InitPacketNumber)
			fmt.Printf(" - ClientTokenLength: %d\n", quicSpec.InitialPacketSpec.ClientTokenLength)

			fmt.Printf("Connection Spec:\n")
			fmt.Printf(" - UDPDatagramMinSize: %d\n", quicSpec.UDPDatagramMinSize)

			// Check ClientHelloSpec
			if quicSpec.ClientHelloSpec != nil {
				fmt.Printf("TLS ClientHello Spec:\n")
				fmt.Printf(" - CipherSuites: %d entries\n", len(quicSpec.ClientHelloSpec.CipherSuites))
				fmt.Printf(" - Extensions: %d entries\n", len(quicSpec.ClientHelloSpec.Extensions))
				fmt.Printf(" - CompressionMethods: %v\n", quicSpec.ClientHelloSpec.CompressionMethods)

				// Show some cipher suites
				if len(quicSpec.ClientHelloSpec.CipherSuites) > 0 {
					fmt.Printf(" - First few CipherSuites: ")
					for i, suite := range quicSpec.ClientHelloSpec.CipherSuites[:min(3, len(quicSpec.ClientHelloSpec.CipherSuites))] {
						if i > 0 {
							fmt.Printf(", ")
						}
						fmt.Printf("0x%04x", suite)
					}
					fmt.Printf("\n")
				}
			}

			// Calculate fingerprint hash
			hasher := getQUICSpecHasher(quicSpec)
			fmt.Printf("Fingerprint Hash: %s\n", hasher)
		} else {
			fmt.Printf("quicSpec field not found in transport\n")
		}

		// Check for other relevant fields
		tlsConfigField := transportValue.FieldByName("tlsConfig")
		if tlsConfigField.IsValid() {
			fmt.Printf("TLS Config present\n")
		}

		dialerField := transportValue.FieldByName("dialer")
		if dialerField.IsValid() {
			fmt.Printf("Custom dialer present\n")
		}

		cachedTransportsField := transportValue.FieldByName("cachedTransports")
		if cachedTransportsField.IsValid() {
			fmt.Printf("Transport cache present\n")
		}
	}

	fmt.Println()
}

func getQUICSpecHasher(spec *quic.QUICSpec) string {
	// Simple hash based on key parameters
	hash := uint32(spec.InitialPacketSpec.SrcConnIDLength)<<24 |
		uint32(spec.InitialPacketSpec.DestConnIDLength)<<16 |
		uint32(spec.UDPDatagramMinSize)<<8

	if spec.ClientHelloSpec != nil {
		hash ^= uint32(len(spec.ClientHelloSpec.CipherSuites))
		hash ^= uint32(len(spec.ClientHelloSpec.Extensions)) << 4
	}

	return fmt.Sprintf("%08x", hash)
}
