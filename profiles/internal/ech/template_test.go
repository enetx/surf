package ech

import (
	"bytes"
	"strings"
	"testing"
)

func TestWireHelperValidation(t *testing.T) {
	for _, raw := range [][]byte{nil, {1}, make([]byte, 39)} {
		if _, _, err := Parse(raw); err == nil {
			t.Fatal("invalid template accepted")
		}
	}
	for _, data := range [][]byte{nil, {0}, {2, 3}, {1, 3, 4}, {4, 3, 4}} {
		if _, err := Versions(data, true); err == nil {
			t.Fatal("invalid version vector accepted")
		}
	}
	for _, name := range []string{"", "127.0.0.1", "[::1]"} {
		if got, err := ServerName(name); err != nil || len(got) != 0 {
			t.Fatal("IP or empty SNI encoded")
		}
	}
	if _, err := ServerName(strings.Repeat("a", 65531)); err == nil {
		t.Fatal("oversized SNI accepted")
	}
	a, _ := ServerName("private.example.")
	b, _ := ServerName("private.example")
	if !bytes.Equal(a, b) {
		t.Fatal("trailing dot changed SNI")
	}
	for _, protocols := range [][]string{{""}, {strings.Repeat("a", 256)}} {
		if _, err := ALPN(protocols); err == nil {
			t.Fatal("invalid ALPN accepted")
		}
	}
	if _, err := ALPN(make([]string, 65534)); err == nil {
		t.Fatal("invalid protocol list accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 40))
	f.Fuzz(func(t *testing.T, raw []byte) { _, _, _ = Parse(raw); _, _ = Versions(raw, true) })
}
