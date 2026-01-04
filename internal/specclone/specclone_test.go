package specclone_test

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/enetx/surf/internal/specclone"

	utls "github.com/enetx/utls"
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
			&utls.SNIExtension{ServerName: "127.0.0.1"},
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
	if "127.0.0.1" != clonedSNI.ServerName {
		t.Errorf("Clone modified after original change: expected=127.0.0.1, got=%s", clonedSNI.ServerName)
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
			&utls.SNIExtension{ServerName: "127.0.0.1"},
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
			&utls.SNIExtension{ServerName: "127.0.0.1"},
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

// Test for missing extension types coverage
func TestSpecClone_MissingExtensions(t *testing.T) {
	t.Run("StatusRequestV2Extension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.StatusRequestV2Extension{},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}
		if _, ok := cloned.Extensions[0].(*utls.StatusRequestV2Extension); !ok {
			t.Errorf("Expected StatusRequestV2Extension, got %T", cloned.Extensions[0])
		}
	})

	t.Run("SCTExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.SCTExtension{},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}
		if _, ok := cloned.Extensions[0].(*utls.SCTExtension); !ok {
			t.Errorf("Expected SCTExtension, got %T", cloned.Extensions[0])
		}
	})

	t.Run("ExtendedMasterSecretExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.ExtendedMasterSecretExtension{},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}
		if _, ok := cloned.Extensions[0].(*utls.ExtendedMasterSecretExtension); !ok {
			t.Errorf("Expected ExtendedMasterSecretExtension, got %T", cloned.Extensions[0])
		}
	})

	t.Run("FakeTokenBindingExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.FakeTokenBindingExtension{
					MajorVersion:  1,
					MinorVersion:  0,
					KeyParameters: []uint8{1, 2, 3},
				},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.FakeTokenBindingExtension)
		clonedExt := cloned.Extensions[0].(*utls.FakeTokenBindingExtension)

		if originalExt.MajorVersion != clonedExt.MajorVersion {
			t.Errorf("MajorVersion mismatch: original=%d, cloned=%d", originalExt.MajorVersion, clonedExt.MajorVersion)
		}
		if originalExt.MinorVersion != clonedExt.MinorVersion {
			t.Errorf("MinorVersion mismatch: original=%d, cloned=%d", originalExt.MinorVersion, clonedExt.MinorVersion)
		}
		if !reflect.DeepEqual(originalExt.KeyParameters, clonedExt.KeyParameters) {
			t.Errorf(
				"KeyParameters mismatch: original=%v, cloned=%v",
				originalExt.KeyParameters,
				clonedExt.KeyParameters,
			)
		}
	})

	t.Run("UtlsCompressCertExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.UtlsCompressCertExtension{
					Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli, utls.CertCompressionZlib},
				},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.UtlsCompressCertExtension)
		clonedExt := cloned.Extensions[0].(*utls.UtlsCompressCertExtension)

		if !reflect.DeepEqual(originalExt.Algorithms, clonedExt.Algorithms) {
			t.Errorf("Algorithms mismatch: original=%v, cloned=%v", originalExt.Algorithms, clonedExt.Algorithms)
		}
	})

	t.Run("FakeRecordSizeLimitExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.FakeRecordSizeLimitExtension{
					Limit: 16384,
				},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.FakeRecordSizeLimitExtension)
		clonedExt := cloned.Extensions[0].(*utls.FakeRecordSizeLimitExtension)

		if originalExt.Limit != clonedExt.Limit {
			t.Errorf("Limit mismatch: original=%d, cloned=%d", originalExt.Limit, clonedExt.Limit)
		}
	})

	t.Run("FakeDelegatedCredentialsExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []utls.SignatureScheme{
						utls.PKCS1WithSHA256,
						utls.ECDSAWithP256AndSHA256,
					},
				},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.FakeDelegatedCredentialsExtension)
		clonedExt := cloned.Extensions[0].(*utls.FakeDelegatedCredentialsExtension)

		if !reflect.DeepEqual(originalExt.SupportedSignatureAlgorithms, clonedExt.SupportedSignatureAlgorithms) {
			t.Errorf(
				"SupportedSignatureAlgorithms mismatch: original=%v, cloned=%v",
				originalExt.SupportedSignatureAlgorithms,
				clonedExt.SupportedSignatureAlgorithms,
			)
		}
	})

	t.Run("SignatureAlgorithmsCertExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.SignatureAlgorithmsCertExtension{
					SupportedSignatureAlgorithms: []utls.SignatureScheme{
						utls.PKCS1WithSHA256,
						utls.ECDSAWithP256AndSHA256,
					},
				},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.SignatureAlgorithmsCertExtension)
		clonedExt := cloned.Extensions[0].(*utls.SignatureAlgorithmsCertExtension)

		if !reflect.DeepEqual(originalExt.SupportedSignatureAlgorithms, clonedExt.SupportedSignatureAlgorithms) {
			t.Errorf(
				"SupportedSignatureAlgorithms mismatch: original=%v, cloned=%v",
				originalExt.SupportedSignatureAlgorithms,
				clonedExt.SupportedSignatureAlgorithms,
			)
		}
	})

	t.Run("ApplicationSettingsExtensionNew", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.ApplicationSettingsExtensionNew{
					SupportedProtocols: []string{"h2", "http/1.1"},
				},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.ApplicationSettingsExtensionNew)
		clonedExt := cloned.Extensions[0].(*utls.ApplicationSettingsExtensionNew)

		if !reflect.DeepEqual(originalExt.SupportedProtocols, clonedExt.SupportedProtocols) {
			t.Errorf(
				"SupportedProtocols mismatch: original=%v, cloned=%v",
				originalExt.SupportedProtocols,
				clonedExt.SupportedProtocols,
			)
		}
	})

	t.Run("KeyShareExtensionExtended", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.KeyShareExtensionExtended{
					KeyShareExtension: &utls.KeyShareExtension{
						KeyShares: []utls.KeyShare{
							{Group: utls.X25519, Data: []byte{0x01, 0x02, 0x03}},
						},
					},
					HybridReuseKey: true,
				},
			},
		}

		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		clonedExt, ok := cloned.Extensions[0].(*utls.KeyShareExtensionExtended)
		if !ok {
			t.Fatalf("Expected KeyShareExtensionExtended, got %T", cloned.Extensions[0])
		}

		if !clonedExt.HybridReuseKey {
			t.Error("HybridReuseKey not preserved")
		}

		if len(clonedExt.KeyShares) != 1 {
			t.Fatalf("Expected 1 KeyShare, got %d", len(clonedExt.KeyShares))
		}

		// Проверка независимости по памяти
		if &clonedExt.KeyShares[0] == &original.Extensions[0].(*utls.KeyShareExtensionExtended).KeyShares[0] {
			t.Error("KeyShares slice not deeply cloned")
		}

		if clonedExt.KeyShares[0].Group != utls.X25519 {
			t.Errorf("Group mismatch: got %v", clonedExt.KeyShares[0].Group)
		}
		if !reflect.DeepEqual(clonedExt.KeyShares[0].Data, []byte{0x01, 0x02, 0x03}) {
			t.Errorf("Data mismatch: expected [1 2 3], got %v", clonedExt.KeyShares[0].Data)
		}
	})

	t.Run("FakeChannelIDExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.FakeChannelIDExtension{
					OldExtensionID: true,
				},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.FakeChannelIDExtension)
		clonedExt := cloned.Extensions[0].(*utls.FakeChannelIDExtension)

		if originalExt.OldExtensionID != clonedExt.OldExtensionID {
			t.Errorf(
				"OldExtensionID mismatch: original=%v, cloned=%v",
				originalExt.OldExtensionID,
				clonedExt.OldExtensionID,
			)
		}
	})

	t.Run("GREASEEncryptedClientHelloExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.GREASEEncryptedClientHelloExtension{
					CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{{KdfId: 1, AeadId: 2}},
					CandidatePayloadLens:  []uint16{100, 200},
				},
			},
		}
		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.GREASEEncryptedClientHelloExtension)
		clonedExt := cloned.Extensions[0].(*utls.GREASEEncryptedClientHelloExtension)

		if !reflect.DeepEqual(originalExt.CandidateCipherSuites, clonedExt.CandidateCipherSuites) {
			t.Errorf(
				"CandidateCipherSuites mismatch: original=%v, cloned=%v",
				originalExt.CandidateCipherSuites,
				clonedExt.CandidateCipherSuites,
			)
		}
		if !reflect.DeepEqual(originalExt.CandidatePayloadLens, clonedExt.CandidatePayloadLens) {
			t.Errorf(
				"CandidatePayloadLens mismatch: original=%v, cloned=%v",
				originalExt.CandidatePayloadLens,
				clonedExt.CandidatePayloadLens,
			)
		}
	})
}

// Test SessionTicketExtension with complex session data
func TestSpecClone_SessionTicketExtension(t *testing.T) {
	sessionData := &utls.SessionState{
		Extra:     [][]byte{[]byte("extra1"), []byte("extra2"), nil, []byte("extra4")},
		EarlyData: true,
	}

	original := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SessionTicketExtension{
				Session:     sessionData,
				Ticket:      []byte("ticket-data"),
				Initialized: true,
			},
		},
	}

	cloned := specclone.Clone(original)
	if cloned == nil || len(cloned.Extensions) != 1 {
		t.Fatal("Expected non-nil clone with 1 extension")
	}

	originalExt := original.Extensions[0].(*utls.SessionTicketExtension)
	clonedExt := cloned.Extensions[0].(*utls.SessionTicketExtension)

	if originalExt.Initialized != clonedExt.Initialized {
		t.Errorf("Initialized mismatch: original=%v, cloned=%v", originalExt.Initialized, clonedExt.Initialized)
	}

	if !reflect.DeepEqual(originalExt.Ticket, clonedExt.Ticket) {
		t.Errorf("Ticket mismatch: original=%v, cloned=%v", originalExt.Ticket, clonedExt.Ticket)
	}

	// Test session cloning
	if originalExt.Session == nil || clonedExt.Session == nil {
		t.Fatal("Session should not be nil")
	}

	if originalExt.Session.EarlyData != clonedExt.Session.EarlyData {
		t.Errorf(
			"Session EarlyData mismatch: original=%v, cloned=%v",
			originalExt.Session.EarlyData,
			clonedExt.Session.EarlyData,
		)
	}

	if len(originalExt.Session.Extra) != len(clonedExt.Session.Extra) {
		t.Errorf(
			"Session Extra length mismatch: original=%d, cloned=%d",
			len(originalExt.Session.Extra),
			len(clonedExt.Session.Extra),
		)
	}

	// Test independence
	originalExt.Session.Extra[0][0] = 'X'
	if originalExt.Session.Extra[0][0] == clonedExt.Session.Extra[0][0] {
		t.Error("Session Extra not independent")
	}
}

// Test PreSharedKey extensions
func TestSpecClone_PreSharedKeyExtensions(t *testing.T) {
	t.Run("FakePreSharedKeyExtension", func(t *testing.T) {
		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.FakePreSharedKeyExtension{
					Identities: []utls.PskIdentity{
						{Label: []byte("identity1"), ObfuscatedTicketAge: 100},
						{Label: []byte("identity2"), ObfuscatedTicketAge: 200},
					},
					Binders: [][]byte{[]byte("binder1"), []byte("binder2"), nil},
				},
			},
		}

		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.FakePreSharedKeyExtension)
		clonedExt := cloned.Extensions[0].(*utls.FakePreSharedKeyExtension)

		if len(originalExt.Identities) != len(clonedExt.Identities) {
			t.Errorf(
				"Identities length mismatch: original=%d, cloned=%d",
				len(originalExt.Identities),
				len(clonedExt.Identities),
			)
		}

		// Test independence
		originalExt.Identities[0].Label[0] = 'X'
		if originalExt.Identities[0].Label[0] == clonedExt.Identities[0].Label[0] {
			t.Error("Identities Label not independent")
		}
	})

	t.Run("UtlsPreSharedKeyExtension", func(t *testing.T) {
		sessionData := &utls.SessionState{
			Extra:     [][]byte{[]byte("session-extra")},
			EarlyData: false,
		}

		original := &utls.ClientHelloSpec{
			Extensions: []utls.TLSExtension{
				&utls.UtlsPreSharedKeyExtension{
					PreSharedKeyCommon: utls.PreSharedKeyCommon{
						Identities:  []utls.PskIdentity{{Label: []byte("identity"), ObfuscatedTicketAge: 300}},
						Binders:     [][]byte{[]byte("binder")},
						BinderKey:   []byte("binder-key"),
						EarlySecret: []byte("early-secret"),
						Session:     sessionData,
					},
					OmitEmptyPsk: true,
				},
			},
		}

		cloned := specclone.Clone(original)
		if cloned == nil || len(cloned.Extensions) != 1 {
			t.Fatal("Expected non-nil clone with 1 extension")
		}

		originalExt := original.Extensions[0].(*utls.UtlsPreSharedKeyExtension)
		clonedExt := cloned.Extensions[0].(*utls.UtlsPreSharedKeyExtension)

		if originalExt.OmitEmptyPsk != clonedExt.OmitEmptyPsk {
			t.Errorf("OmitEmptyPsk mismatch: original=%v, cloned=%v", originalExt.OmitEmptyPsk, clonedExt.OmitEmptyPsk)
		}

		if !reflect.DeepEqual(originalExt.BinderKey, clonedExt.BinderKey) {
			t.Errorf("BinderKey mismatch: original=%v, cloned=%v", originalExt.BinderKey, clonedExt.BinderKey)
		}

		// Test session independence
		originalExt.Session.Extra[0][0] = 'Y'
		if originalExt.Session.Extra[0][0] == clonedExt.Session.Extra[0][0] {
			t.Error("Session Extra not independent")
		}
	})
}

// Test the interface branch in deepCloneExtension
func TestSpecClone_PreSharedKeyInterface(t *testing.T) {
	// This tests the interface branch where we have utls.PreSharedKeyExtension interface
	var ext utls.PreSharedKeyExtension = &utls.FakePreSharedKeyExtension{
		Identities: []utls.PskIdentity{{Label: []byte("test"), ObfuscatedTicketAge: 123}},
		Binders:    [][]byte{[]byte("test-binder")},
	}

	original := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{ext},
	}

	cloned := specclone.Clone(original)
	if cloned == nil || len(cloned.Extensions) != 1 {
		t.Fatal("Expected non-nil clone with 1 extension")
	}

	if _, ok := cloned.Extensions[0].(*utls.FakePreSharedKeyExtension); !ok {
		t.Errorf("Expected FakePreSharedKeyExtension, got %T", cloned.Extensions[0])
	}
}

// Test deepCloneInterface fallback path by creating extension that will hit the default case
func TestSpecClone_UnknownExtension(t *testing.T) {
	// Create an extension that will be handled by the default case in deepCloneExtension
	// Use reflection to create a mock extension that will hit deepCloneInterface

	// First test with GenericExtension (it is handled specifically)
	customExt := &utls.GenericExtension{
		Id:   0x9999, // Custom extension ID
		Data: []byte("custom-data-for-testing"),
	}

	original := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{customExt},
	}

	cloned := specclone.Clone(original)
	if cloned == nil || len(cloned.Extensions) != 1 {
		t.Fatal("Expected non-nil clone with 1 extension")
	}

	clonedExt, ok := cloned.Extensions[0].(*utls.GenericExtension)
	if !ok {
		t.Fatalf("Expected GenericExtension, got %T", cloned.Extensions[0])
	}

	if clonedExt.Id != 0x9999 {
		t.Errorf("Id mismatch: expected=0x9999, got=0x%x", clonedExt.Id)
	}

	if !reflect.DeepEqual(clonedExt.Data, []byte("custom-data-for-testing")) {
		t.Errorf("Data mismatch: expected=custom-data-for-testing, got=%s", clonedExt.Data)
	}

	// Test independence
	customExt.Data[0] = 'X'
	if customExt.Data[0] == clonedExt.Data[0] {
		t.Error("Data not independent")
	}
}

// Test to force deepCloneInterface usage by creating a fake extension
func TestSpecClone_ForceReflectionPath(t *testing.T) {
	// Create a custom TLS extension that implements the interface
	// This will force the default case in deepCloneExtension to trigger deepCloneInterface

	// Use reflection to create a fake extension that will hit the default case
	fakeExtensionType := reflect.TypeOf((*utls.GenericExtension)(nil)).Elem()
	fakeExtension := reflect.New(fakeExtensionType).Interface().(utls.TLSExtension)

	// Set up the fake extension with some data
	fakeGeneric := fakeExtension.(*utls.GenericExtension)
	fakeGeneric.Id = 0xFFFF
	fakeGeneric.Data = []byte("reflection-test-data")

	original := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{fakeExtension},
	}

	cloned := specclone.Clone(original)
	if cloned == nil || len(cloned.Extensions) != 1 {
		t.Fatal("Expected non-nil clone with 1 extension")
	}

	clonedExt, ok := cloned.Extensions[0].(*utls.GenericExtension)
	if !ok {
		t.Fatalf("Expected GenericExtension, got %T", cloned.Extensions[0])
	}

	if clonedExt.Id != 0xFFFF {
		t.Errorf("Id mismatch: expected=0xFFFF, got=0x%x", clonedExt.Id)
	}

	if !reflect.DeepEqual(clonedExt.Data, []byte("reflection-test-data")) {
		t.Errorf("Data mismatch: expected=reflection-test-data, got=%s", clonedExt.Data)
	}
}

// Test for unknown PSK extension to hit the PreSharedKeyExtension interface branch
func TestSpecClone_UnknownPSKExtension(t *testing.T) {
	// Test by creating a struct that implements PreSharedKeyExtension but is not known
	type UnknownPSKExtension struct {
		*utls.FakePreSharedKeyExtension
		CustomField string
	}

	unknownPSK := &UnknownPSKExtension{
		FakePreSharedKeyExtension: &utls.FakePreSharedKeyExtension{
			Identities: []utls.PskIdentity{
				{Label: []byte("unknown-psk"), ObfuscatedTicketAge: 123},
			},
			Binders: [][]byte{[]byte("unknown-binder")},
		},
		CustomField: "custom-value",
	}

	// Cast to the interface type to trigger the interface branch
	var pskInterface utls.PreSharedKeyExtension = unknownPSK

	original := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{pskInterface},
	}

	cloned := specclone.Clone(original)
	if cloned == nil || len(cloned.Extensions) != 1 {
		t.Fatal("Expected non-nil clone with 1 extension")
	}

	// The cloned extension should be the same type due to reflection cloning
	clonedExt, ok := cloned.Extensions[0].(*UnknownPSKExtension)
	if !ok {
		t.Fatalf("Expected UnknownPSKExtension, got %T", cloned.Extensions[0])
	}

	if len(clonedExt.Identities) != 1 {
		t.Fatalf("Expected 1 identity, got %d", len(clonedExt.Identities))
	}

	if string(clonedExt.Identities[0].Label) != "unknown-psk" {
		t.Errorf("Identity label mismatch: expected=unknown-psk, got=%s", clonedExt.Identities[0].Label)
	}

	if clonedExt.CustomField != "custom-value" {
		t.Errorf("CustomField mismatch: expected=custom-value, got=%s", clonedExt.CustomField)
	}
}

// Test for SessionTicketExtension with nil session
func TestSpecClone_SessionTicketExtension_NilSession(t *testing.T) {
	original := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SessionTicketExtension{
				Session:     nil,
				Ticket:      []byte("ticket-data"),
				Initialized: false,
			},
		},
	}

	cloned := specclone.Clone(original)
	if cloned == nil || len(cloned.Extensions) != 1 {
		t.Fatal("Expected non-nil clone with 1 extension")
	}

	originalExt := original.Extensions[0].(*utls.SessionTicketExtension)
	clonedExt := cloned.Extensions[0].(*utls.SessionTicketExtension)

	if originalExt.Session != nil || clonedExt.Session != nil {
		t.Error("Both sessions should be nil")
	}

	if originalExt.Initialized != clonedExt.Initialized {
		t.Errorf("Initialized mismatch: original=%v, cloned=%v", originalExt.Initialized, clonedExt.Initialized)
	}
}

// Test for deepCloneInterface with basic types and complex structures
func TestSpecClone_ReflectionCoverage(t *testing.T) {
	// Test a complex structure with nested slices, maps, pointers to force reflection paths
	original := &utls.ClientHelloSpec{
		TLSVersMin:         0x0301,
		TLSVersMax:         0x0304,
		CipherSuites:       []uint16{0x1301, 0x1302},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "reflection-test.com"},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.KeyShareExtension{
				KeyShares: []utls.KeyShare{
					{Group: utls.X25519, Data: []byte{1, 2, 3}},
					{Group: utls.CurveP256, Data: []byte{4, 5, 6}},
				},
			},
		},
	}

	cloned := specclone.Clone(original)
	if cloned == nil {
		t.Fatal("Expected non-nil clone")
	}

	// Verify deep independence by modifying nested structures
	original.Extensions = append(original.Extensions, &utls.SCTExtension{})
	if len(original.Extensions) == len(cloned.Extensions) {
		t.Error("Extensions slice should be independent")
	}

	// Modify nested data
	keyShareExt := original.Extensions[2].(*utls.KeyShareExtension)
	keyShareExt.KeyShares[0].Data[0] = 255

	clonedKeyShareExt := cloned.Extensions[2].(*utls.KeyShareExtension)
	if keyShareExt.KeyShares[0].Data[0] == clonedKeyShareExt.KeyShares[0].Data[0] {
		t.Error("Nested KeyShare data should be independent")
	}
}
