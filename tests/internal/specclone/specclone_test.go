package specclone_test

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/enetx/surf/internal/specclone"

	utls "github.com/refraction-networking/utls"
)

func TestSpecClone_NilInput(t *testing.T) {
	result := specclone.Clone(nil)
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}
}

func TestSpecClone_BasicFields(t *testing.T) {
	original := &utls.ClientHelloSpec{
		TLSVersMin: 0x0301,
		TLSVersMax: 0x0303,
		GetSessionID: func([]byte) [32]byte {
			return [32]byte{1, 2, 3}
		},
	}

	cloned := specclone.Clone(original)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if original.TLSVersMin != cloned.TLSVersMin {
		t.Errorf("TLSVersMin mismatch: original=%x, cloned=%x", original.TLSVersMin, cloned.TLSVersMin)
	}
	if original.TLSVersMax != cloned.TLSVersMax {
		t.Errorf("TLSVersMax mismatch: original=%x, cloned=%x", original.TLSVersMax, cloned.TLSVersMax)
	}
	if cloned.GetSessionID == nil {
		t.Error("GetSessionID should not be nil")
	}

	// Verify function independence
	if original.GetSessionID != nil && cloned.GetSessionID != nil {
		originalResult := original.GetSessionID([]byte{})
		clonedResult := cloned.GetSessionID([]byte{})
		if originalResult != clonedResult {
			t.Errorf("Function results differ: original=%v, cloned=%v", originalResult, clonedResult)
		}
	}
}

func TestSpecClone_CipherSuites(t *testing.T) {
	original := &utls.ClientHelloSpec{
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303},
	}

	cloned := specclone.Clone(original)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if cloned.CipherSuites == nil {
		t.Fatal("Expected non-nil CipherSuites")
	}
	if len(original.CipherSuites) != len(cloned.CipherSuites) {
		t.Errorf(
			"CipherSuites length mismatch: original=%d, cloned=%d",
			len(original.CipherSuites),
			len(cloned.CipherSuites),
		)
	}
	for i, suite := range original.CipherSuites {
		if suite != cloned.CipherSuites[i] {
			t.Errorf("CipherSuite[%d] mismatch: original=%x, cloned=%x", i, suite, cloned.CipherSuites[i])
		}
	}

	// Verify independence - modifying original should not affect clone
	original.CipherSuites[0] = 0xFFFF
	if original.CipherSuites[0] == cloned.CipherSuites[0] {
		t.Error("CipherSuites not independent")
	}
	if uint16(0x1301) != cloned.CipherSuites[0] {
		t.Errorf("Clone modified after original change: expected=0x1301, got=%x", cloned.CipherSuites[0])
	}
}

func TestSpecClone_CompressionMethods(t *testing.T) {
	original := &utls.ClientHelloSpec{
		CompressionMethods: []uint8{0, 1, 2},
	}

	cloned := specclone.Clone(original)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if cloned.CompressionMethods == nil {
		t.Fatal("Expected non-nil CompressionMethods")
	}
	if len(original.CompressionMethods) != len(cloned.CompressionMethods) {
		t.Errorf(
			"CompressionMethods length mismatch: original=%d, cloned=%d",
			len(original.CompressionMethods),
			len(cloned.CompressionMethods),
		)
	}
	for i, method := range original.CompressionMethods {
		if method != cloned.CompressionMethods[i] {
			t.Errorf("CompressionMethod[%d] mismatch: original=%d, cloned=%d", i, method, cloned.CompressionMethods[i])
		}
	}

	// Verify independence
	original.CompressionMethods[0] = 255
	if original.CompressionMethods[0] == cloned.CompressionMethods[0] {
		t.Error("CompressionMethods not independent")
	}
	if uint8(0) != cloned.CompressionMethods[0] {
		t.Errorf("Clone modified after original change: expected=0, got=%d", cloned.CompressionMethods[0])
	}
}

func TestSpecClone_Extensions_SNI(t *testing.T) {
	original := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "example.com"},
		},
	}

	cloned := specclone.Clone(original)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if len(cloned.Extensions) != 1 {
		t.Fatalf("Expected 1 extension, got %d", len(cloned.Extensions))
	}

	originalSNI := original.Extensions[0].(*utls.SNIExtension)
	clonedSNI := cloned.Extensions[0].(*utls.SNIExtension)

	if originalSNI.ServerName != clonedSNI.ServerName {
		t.Errorf("ServerName mismatch: original=%s, cloned=%s", originalSNI.ServerName, clonedSNI.ServerName)
	}

	// Verify independence
	originalSNI.ServerName = "changed.com"
	if originalSNI.ServerName == clonedSNI.ServerName {
		t.Error("SNI extensions not independent")
	}
	if "example.com" != clonedSNI.ServerName {
		t.Errorf("Clone modified after original change: expected=example.com, got=%s", clonedSNI.ServerName)
	}
}

func TestSpecClone_Extensions_ALPN(t *testing.T) {
	original := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.ALPNExtension{
				AlpnProtocols: []string{"h2", "http/1.1"},
			},
		},
	}

	cloned := specclone.Clone(original)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if len(cloned.Extensions) != 1 {
		t.Fatalf("Expected 1 extension, got %d", len(cloned.Extensions))
	}

	originalALPN := original.Extensions[0].(*utls.ALPNExtension)
	clonedALPN := cloned.Extensions[0].(*utls.ALPNExtension)

	if len(originalALPN.AlpnProtocols) != len(clonedALPN.AlpnProtocols) {
		t.Errorf(
			"AlpnProtocols length mismatch: original=%d, cloned=%d",
			len(originalALPN.AlpnProtocols),
			len(clonedALPN.AlpnProtocols),
		)
	}
	for i, proto := range originalALPN.AlpnProtocols {
		if proto != clonedALPN.AlpnProtocols[i] {
			t.Errorf("AlpnProtocol[%d] mismatch: original=%s, cloned=%s", i, proto, clonedALPN.AlpnProtocols[i])
		}
	}

	// Verify independence
	originalALPN.AlpnProtocols[0] = "h3"
	if originalALPN.AlpnProtocols[0] == clonedALPN.AlpnProtocols[0] {
		t.Error("ALPN extensions not independent")
	}
	if "h2" != clonedALPN.AlpnProtocols[0] {
		t.Errorf("Clone modified after original change: expected=h2, got=%s", clonedALPN.AlpnProtocols[0])
	}
}

func TestSpecClone_Extensions_NilExtension(t *testing.T) {
	original := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "example.com"},
			nil,
			&utls.ALPNExtension{AlpnProtocols: []string{"h2"}},
		},
	}

	cloned := specclone.Clone(original)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if len(cloned.Extensions) != 3 {
		t.Fatalf("Expected 3 extensions, got %d", len(cloned.Extensions))
	}

	if cloned.Extensions[0] == nil {
		t.Error("Expected first extension to be non-nil")
	}
	if cloned.Extensions[1] != nil {
		t.Error("Expected second extension to be nil")
	}
	if cloned.Extensions[2] == nil {
		t.Error("Expected third extension to be non-nil")
	}
}

func TestSpecClone_Firefox120(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
	if err != nil {
		t.Fatalf("Error getting Firefox spec: %v", err)
	}

	cloned := specclone.Clone(&spec)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if spec.TLSVersMin != cloned.TLSVersMin {
		t.Errorf("TLSVersMin mismatch: original=%x, cloned=%x", spec.TLSVersMin, cloned.TLSVersMin)
	}
	if spec.TLSVersMax != cloned.TLSVersMax {
		t.Errorf("TLSVersMax mismatch: original=%x, cloned=%x", spec.TLSVersMax, cloned.TLSVersMax)
	}
	if len(spec.CipherSuites) != len(cloned.CipherSuites) {
		t.Errorf(
			"CipherSuites length mismatch: original=%d, cloned=%d",
			len(spec.CipherSuites),
			len(cloned.CipherSuites),
		)
	}
	if len(spec.Extensions) != len(cloned.Extensions) {
		t.Errorf("Extensions length mismatch: original=%d, cloned=%d", len(spec.Extensions), len(cloned.Extensions))
	}

	// Verify cipher suites are equal but independent
	for i, suite := range spec.CipherSuites {
		if suite != cloned.CipherSuites[i] {
			t.Errorf("CipherSuite[%d] mismatch: original=%x, cloned=%x", i, suite, cloned.CipherSuites[i])
		}
	}

	if len(spec.CipherSuites) > 0 {
		originalSuite := spec.CipherSuites[0]
		spec.CipherSuites[0] = 0xFFFF
		if spec.CipherSuites[0] == cloned.CipherSuites[0] {
			t.Error("CipherSuites not independent")
		}
		if originalSuite != cloned.CipherSuites[0] {
			t.Errorf(
				"Clone changed after original modification: expected=%x, got=%x",
				originalSuite,
				cloned.CipherSuites[0],
			)
		}
	}

	// Verify extensions independence
	for i, ext := range spec.Extensions {
		if ext == nil {
			continue
		}
		clonedExt := cloned.Extensions[i]
		if reflect.TypeOf(ext) != reflect.TypeOf(clonedExt) {
			t.Errorf("Extension %d type mismatch: original=%T, cloned=%T", i, ext, clonedExt)
		}
	}
}

func TestSpecClone_Chrome120(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
	if err != nil {
		t.Fatalf("Error getting Chrome spec: %v", err)
	}

	cloned := specclone.Clone(&spec)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if spec.TLSVersMin != cloned.TLSVersMin {
		t.Errorf("TLSVersMin mismatch: original=%x, cloned=%x", spec.TLSVersMin, cloned.TLSVersMin)
	}
	if spec.TLSVersMax != cloned.TLSVersMax {
		t.Errorf("TLSVersMax mismatch: original=%x, cloned=%x", spec.TLSVersMax, cloned.TLSVersMax)
	}
	if len(spec.CipherSuites) != len(cloned.CipherSuites) {
		t.Errorf(
			"CipherSuites length mismatch: original=%d, cloned=%d",
			len(spec.CipherSuites),
			len(cloned.CipherSuites),
		)
	}
	if len(spec.Extensions) != len(cloned.Extensions) {
		t.Errorf("Extensions length mismatch: original=%d, cloned=%d", len(spec.Extensions), len(cloned.Extensions))
	}
}

func TestSpecClone_Safari16(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloSafari_16_0)
	if err != nil {
		t.Fatalf("Error getting Safari spec: %v", err)
	}

	cloned := specclone.Clone(&spec)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if spec.TLSVersMin != cloned.TLSVersMin {
		t.Errorf("TLSVersMin mismatch: original=%x, cloned=%x", spec.TLSVersMin, cloned.TLSVersMin)
	}
	if spec.TLSVersMax != cloned.TLSVersMax {
		t.Errorf("TLSVersMax mismatch: original=%x, cloned=%x", spec.TLSVersMax, cloned.TLSVersMax)
	}
	if len(spec.CipherSuites) != len(cloned.CipherSuites) {
		t.Errorf(
			"CipherSuites length mismatch: original=%d, cloned=%d",
			len(spec.CipherSuites),
			len(cloned.CipherSuites),
		)
	}
	if len(spec.Extensions) != len(cloned.Extensions) {
		t.Errorf("Extensions length mismatch: original=%d, cloned=%d", len(spec.Extensions), len(cloned.Extensions))
	}
}

func TestSpecClone_Edge106(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloEdge_106)
	if err != nil {
		t.Fatalf("Error getting Edge spec: %v", err)
	}

	cloned := specclone.Clone(&spec)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if spec.TLSVersMin != cloned.TLSVersMin {
		t.Errorf("TLSVersMin mismatch: original=%x, cloned=%x", spec.TLSVersMin, cloned.TLSVersMin)
	}
	if spec.TLSVersMax != cloned.TLSVersMax {
		t.Errorf("TLSVersMax mismatch: original=%x, cloned=%x", spec.TLSVersMax, cloned.TLSVersMax)
	}
	if len(spec.CipherSuites) != len(cloned.CipherSuites) {
		t.Errorf(
			"CipherSuites length mismatch: original=%d, cloned=%d",
			len(spec.CipherSuites),
			len(cloned.CipherSuites),
		)
	}
	if len(spec.Extensions) != len(cloned.Extensions) {
		t.Errorf("Extensions length mismatch: original=%d, cloned=%d", len(spec.Extensions), len(cloned.Extensions))
	}
}

func TestSpecClone_iOS12(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloIOS_12_1)
	if err != nil {
		t.Fatalf("Error getting iOS spec: %v", err)
	}

	cloned := specclone.Clone(&spec)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if spec.TLSVersMin != cloned.TLSVersMin {
		t.Errorf("TLSVersMin mismatch: original=%x, cloned=%x", spec.TLSVersMin, cloned.TLSVersMin)
	}
	if spec.TLSVersMax != cloned.TLSVersMax {
		t.Errorf("TLSVersMax mismatch: original=%x, cloned=%x", spec.TLSVersMax, cloned.TLSVersMax)
	}
	if len(spec.CipherSuites) != len(cloned.CipherSuites) {
		t.Errorf(
			"CipherSuites length mismatch: original=%d, cloned=%d",
			len(spec.CipherSuites),
			len(cloned.CipherSuites),
		)
	}
	if len(spec.Extensions) != len(cloned.Extensions) {
		t.Errorf("Extensions length mismatch: original=%d, cloned=%d", len(spec.Extensions), len(cloned.Extensions))
	}
}

func TestSpecClone_Android11(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloAndroid_11_OkHttp)
	if err != nil {
		t.Fatalf("Error getting Android spec: %v", err)
	}

	cloned := specclone.Clone(&spec)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if spec.TLSVersMin != cloned.TLSVersMin {
		t.Errorf("TLSVersMin mismatch: original=%x, cloned=%x", spec.TLSVersMin, cloned.TLSVersMin)
	}
	if spec.TLSVersMax != cloned.TLSVersMax {
		t.Errorf("TLSVersMax mismatch: original=%x, cloned=%x", spec.TLSVersMax, cloned.TLSVersMax)
	}
	if len(spec.CipherSuites) != len(cloned.CipherSuites) {
		t.Errorf(
			"CipherSuites length mismatch: original=%d, cloned=%d",
			len(spec.CipherSuites),
			len(cloned.CipherSuites),
		)
	}
	if len(spec.Extensions) != len(cloned.Extensions) {
		t.Errorf("Extensions length mismatch: original=%d, cloned=%d", len(spec.Extensions), len(cloned.Extensions))
	}
}

func TestSpecClone_EmptySpec(t *testing.T) {
	original := &utls.ClientHelloSpec{}
	cloned := specclone.Clone(original)

	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}
	if original.TLSVersMin != cloned.TLSVersMin {
		t.Errorf("TLSVersMin mismatch: original=%x, cloned=%x", original.TLSVersMin, cloned.TLSVersMin)
	}
	if original.TLSVersMax != cloned.TLSVersMax {
		t.Errorf("TLSVersMax mismatch: original=%x, cloned=%x", original.TLSVersMax, cloned.TLSVersMax)
	}
	if cloned.CipherSuites != nil {
		t.Error("Expected nil CipherSuites")
	}
	if cloned.CompressionMethods != nil {
		t.Error("Expected nil CompressionMethods")
	}
	if cloned.Extensions != nil {
		t.Error("Expected nil Extensions")
	}
}

func TestSpecClone_MemoryIndependence(t *testing.T) {
	original := &utls.ClientHelloSpec{
		CipherSuites: []uint16{0x1301, 0x1302},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "original.com"},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		},
	}

	cloned := specclone.Clone(original)

	// Verify different memory addresses for slices
	if len(original.CipherSuites) > 0 && len(cloned.CipherSuites) > 0 {
		originalPtr := (*reflect.SliceHeader)(unsafe.Pointer(&original.CipherSuites)).Data
		clonedPtr := (*reflect.SliceHeader)(unsafe.Pointer(&specclone.Clone(original).CipherSuites)).Data
		if originalPtr == clonedPtr {
			t.Error("CipherSuites should have different memory addresses")
		}
	}

	// Verify different memory addresses for extensions slice
	if len(original.Extensions) > 0 && len(cloned.Extensions) > 0 {
		originalPtr := (*reflect.SliceHeader)(unsafe.Pointer(&original.Extensions)).Data
		clonedPtr := (*reflect.SliceHeader)(unsafe.Pointer(&specclone.Clone(original).Extensions)).Data
		if originalPtr == clonedPtr {
			t.Error("Extensions should have different memory addresses")
		}
	}
}

// Benchmark tests
func BenchmarkSpecClone_Firefox(b *testing.B) {
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
	if err != nil {
		b.Fatalf("Error getting spec: %v", err)
	}

	for b.Loop() {
		_ = specclone.Clone(&spec)
	}
}

func BenchmarkSpecClone_Chrome(b *testing.B) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
	if err != nil {
		b.Fatalf("Error getting spec: %v", err)
	}

	for b.Loop() {
		_ = specclone.Clone(&spec)
	}
}

func BenchmarkSpecClone_Safari(b *testing.B) {
	spec, err := utls.UTLSIdToSpec(utls.HelloSafari_16_0)
	if err != nil {
		b.Fatalf("Error getting spec: %v", err)
	}

	for b.Loop() {
		_ = specclone.Clone(&spec)
	}
}

func BenchmarkSpecClone_Edge(b *testing.B) {
	spec, err := utls.UTLSIdToSpec(utls.HelloEdge_106)
	if err != nil {
		b.Fatalf("Error getting spec: %v", err)
	}

	for b.Loop() {
		_ = specclone.Clone(&spec)
	}
}

func BenchmarkSpecClone_Simple(b *testing.B) {
	spec := &utls.ClientHelloSpec{
		TLSVersMin:   0x0301,
		TLSVersMax:   0x0303,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "example.com"},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		},
	}

	for b.Loop() {
		_ = specclone.Clone(spec)
	}
}

// Helper function similar to the user's example
func TestClone(t *testing.T) {
	profiles := []utls.ClientHelloID{
		utls.HelloFirefox_120,
		utls.HelloChrome_120,
		utls.HelloSafari_16_0,
		utls.HelloEdge_106,
		utls.HelloIOS_12_1,
		utls.HelloAndroid_11_OkHttp,
	}

	for _, profile := range profiles {
		spec, err := utls.UTLSIdToSpec(profile)
		if err != nil {
			t.Fatalf("Error getting spec for %v: %v", profile, err)
		}

		cloned := specclone.Clone(&spec)

		// Basic validation without output
		if spec.TLSVersMin != cloned.TLSVersMin {
			t.Errorf("%v: TLSVersMin mismatch", profile)
		}
		if len(spec.CipherSuites) != len(cloned.CipherSuites) {
			t.Errorf("%v: CipherSuites length mismatch", profile)
		}

		// Verify extensions type matching
		for i, ext := range spec.Extensions {
			if ext == nil {
				continue
			}
			clonedExt := cloned.Extensions[i]
			if reflect.TypeOf(ext) != reflect.TypeOf(clonedExt) {
				t.Errorf("%v: Extension %d type mismatch: %T vs %T", profile, i, ext, clonedExt)
			}
		}
	}
}
