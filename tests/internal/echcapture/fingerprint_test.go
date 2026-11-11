package echcapture

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestTransportFingerprintRetainsCapabilities(t *testing.T) {
	// ID 0xff02de1a is a real legacy minimum-ACK-delay parameter even
	// though its value also satisfies the reserved GREASE congruence.
	legacy := []byte{0xc0, 0, 0, 0, 0xff, 2, 0xde, 0x1a, 2, 0x43, 0xe8}
	rtt1 := []byte{0x71, 0x27, 4, 0x80, 0, 0xdc, 0x2b}
	rtt2 := []byte{0x71, 0x27, 4, 0x80, 0, 0xce, 0x60}
	base, err := transportFeature(append(bytes.Clone(legacy), rtt1...), "chrome")
	if err != nil || !strings.Contains(base, "4278378010/") || !strings.Contains(base, "12583/2/1:rtt-us:minimal") {
		t.Fatalf("real capabilities disappeared: %s, %v", base, err)
	}
	other, _ := transportFeature(append(bytes.Clone(legacy), rtt2...), "chrome")
	if base != other {
		t.Fatal("network RTT value was treated as a fixed profile value")
	}
	missing, _ := transportFeature(legacy, "chrome")
	if missing == base {
		t.Fatal("missing RTT hint was hidden by normalization")
	}
	small, _ := transportFeature(append(bytes.Clone(legacy), []byte{0x71, 0x27, 2, 0x76, 0xb0}...), "chrome")
	if small != base {
		t.Fatal("a smaller real RTT changed the stable encoding policy")
	}
	nonminimal, _ := transportFeature(append(bytes.Clone(legacy), []byte{0x71, 0x27, 4, 0x80, 0, 0x36, 0xb0}...), "chrome")
	if nonminimal == base {
		t.Fatal("nonminimal RTT encoding disappeared during normalization")
	}
	zero, _ := transportFeature(append(bytes.Clone(legacy), []byte{0x71, 0x27, 1, 0}...), "chrome")
	if zero == base {
		t.Fatal("a zero RTT hint was mistaken for a positive measurement")
	}
	legacy[len(legacy)-1] ^= 1
	changed, _ := transportFeature(append(legacy, rtt1...), "chrome")
	if changed == base {
		t.Fatal("minimum ACK delay was mistaken for GREASE")
	}
	for _, invalid := range [][]byte{{0x40}, {1, 4, 0}, {1, 0, 1, 0}, {0x71, 0x27, 1, 0x40}, {0x71, 0x27, 2, 0, 0}, {17, 4, 0, 0, 0, 1}} {
		if _, err := transportFeature(invalid, "chrome"); err == nil {
			t.Fatalf("accepted invalid QUIC parameters %x", invalid)
		}
	}
}

func TestFingerprintPermutationPolicy(t *testing.T) {
	ref := nativeReferences(t)[0]
	h, _ := ReadClientHello(ref.Inner)
	// Keep the engine-owned PSK last; only move unrelated extensions.
	h.Extensions[1], h.Extensions[2] = h.Extensions[2], h.Extensions[1]
	moved, _ := h.Marshal()
	for _, tc := range []struct {
		browser, transport string
		equal              bool
	}{
		{"chrome", "tcp", true}, {"chrome", "quic", true},
		{"firefox", "quic", true}, {"firefox", "tcp", false},
	} {
		a, _ := StableFingerprint(ref.Inner, tc.browser, tc.transport)
		b, _ := StableFingerprint(moved, tc.browser, tc.transport)
		if reflect.DeepEqual(a, b) != tc.equal {
			t.Fatalf("wrong extension permutation rule for %s/%s", tc.browser, tc.transport)
		}
	}
	a := []byte{17, 12, 0, 0, 0, 1, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf, 4, 1, 20}
	b := []byte{4, 1, 20, 17, 12, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 1}
	ca, _ := transportFeature(a, "chrome")
	cb, _ := transportFeature(b, "chrome")
	fa, _ := transportFeature(a, "firefox")
	fb, _ := transportFeature(b, "firefox")
	if ca != cb || fa == fb {
		t.Fatal("QUIC parameter/version ordering policy changed")
	}
}

func TestExtensionFingerprintValidation(t *testing.T) {
	for _, ext := range []Extension{
		{10, []byte{0}}, {13, []byte{0, 1, 0}}, {43, []byte{1, 3}},
		{41, []byte{0}}, {44, []byte{0, 2, 0}}, {51, []byte{0}},
		{51, []byte{0, 4, 0, 29, 0, 0}}, {65037, []byte{0}},
	} {
		if _, err := extensionFeature(ext, "chrome"); err == nil {
			t.Fatalf("accepted malformed extension %d", ext.ID)
		}
	}
	for _, ext := range []Extension{{35, []byte{1, 2}}, {44, []byte{0, 1, 3}}, {65037, []byte{1}}, {65037, []byte{0, 0, 1, 0, 1, 7, 0, 0, 0, 1, 2}}, {12345, []byte{1, 2}}} {
		if _, err := extensionFeature(ext, "chrome"); err != nil {
			t.Fatalf("rejected extension %d: %v", ext.ID, err)
		}
	}
}
