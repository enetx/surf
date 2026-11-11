package ech

import (
	"testing"

	utls "github.com/enetx/utls"
)

func TestInnerLengthOmitsInactiveEarlyData(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1303, 0x1302}
	extensions := []utls.TLSExtension{&utls.SNIExtension{ServerName: "example.com"},
		&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}}, &utls.GenericExtension{Id: 13}}
	want := InnerLength(ciphers, []uint8{0}, extensions)
	if want != 175 {
		t.Fatalf("base inner estimate = %d", want)
	}
	withEarly := append(extensions, &utls.EarlyDataExtension{})
	if got := InnerLength(ciphers, []uint8{0}, withEarly); got != want {
		t.Fatalf("inactive early_data changed cold estimate: %d != %d", got, want)
	}
	withActive := append(extensions, &utls.GenericExtension{Id: 42})
	if got := InnerLength(ciphers, []uint8{0}, withActive); got != want+2 {
		t.Fatalf("active early_data reference: %d != %d", got, want+2)
	}
}
