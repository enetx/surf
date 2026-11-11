package ech_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/enetx/surf/profiles/chrome/common"
	"github.com/enetx/surf/profiles/firefox/desktop"
	"github.com/enetx/surf/tests/internal/echcapture"
	utls "github.com/enetx/utls"
	"golang.org/x/crypto/cryptobyte"
)

type extension struct {
	ID   uint16
	Data []byte
}

// Parse independently of the profile parser: these are captured handshake
// messages, including their four-byte header, not TLS records.
func hello(t *testing.T, raw []byte) ([]uint16, []extension) {
	t.Helper()
	s := cryptobyte.String(raw)
	var body, sid, ciphers, compression, extensions cryptobyte.String
	var typ uint8
	if !s.ReadUint8(&typ) || typ != 1 || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() ||
		!body.Skip(34) || !body.ReadUint8LengthPrefixed(&sid) || !body.ReadUint16LengthPrefixed(&ciphers) ||
		!body.ReadUint8LengthPrefixed(&compression) || !body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		t.Fatal("malformed captured ClientHello")
	}
	var ids []uint16
	for !ciphers.Empty() {
		var id uint16
		if !ciphers.ReadUint16(&id) {
			t.Fatal("truncated cipher")
		}
		ids = append(ids, id)
	}
	var exts []extension
	for !extensions.Empty() {
		var id uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&data) {
			t.Fatal("truncated extension")
		}
		exts = append(exts, extension{id, data})
	}
	return ids, exts
}

func TestChromeInnerMatchesNativeCapture(t *testing.T) {
	testNativeInnerFixtures(t, "chrome-157-tcp-*.json", 2, common.ClientHelloInner)
	testNativeInnerFixtures(t, "chrome-157-quic-*.json", 1, common.ClientHelloInner)
}

func TestFirefoxInnerMatchesNativeCapture(t *testing.T) {
	testNativeInnerFixtures(t, "firefox-160-tcp-*.json", 1, desktop.ClientHelloInner)
	testNativeInnerFixtures(t, "firefox-160-quic-*.json", 1, desktop.ClientHelloInner)
}

func TestResumedInnerMatchesNativeCapture(t *testing.T) {
	testNativeInnerFixtures(t, "resumption/native/chrome-157-tcp-*.json", 2, common.ClientHelloInner)
	testNativeInnerFixtures(t, "resumption/native/chrome-157-quic-*.json", 2, common.ClientHelloInner)
	testNativeInnerFixtures(t, "resumption/native/firefox-160-tcp-*.json", 1, desktop.ClientHelloInner)
	testNativeInnerFixtures(t, "resumption/native/firefox-160-quic-*.json", 1, desktop.ClientHelloInner)
}

func testNativeInnerFixtures(t *testing.T, pattern string, count int, policy utls.ECHClientHelloInnerFunc) {
	t.Helper()
	paths, err := filepath.Glob("../../testdata/wire/ech/" + pattern)
	if err != nil || len(paths) != count {
		t.Fatalf("capture fixtures: %v, %v", paths, err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			var capture struct {
				Outer, Inner []byte
				Transport    string
				PSK          struct {
					Outer string `json:"outer_policy"`
				}
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &capture); err != nil {
				t.Fatal(err)
			}
			_, outer := hello(t, capture.Outer)
			wantCiphers, want := hello(t, capture.Inner)
			var name string
			for _, ext := range want {
				if ext.ID == 0 {
					name = string(ext.Data[5:])
				}
			}
			protocols := []string{"h2", "http/1.1"}
			if capture.Transport == "quic" {
				protocols = []string{"h3"}
			}
			info := utls.ECHClientHelloInfo{ClientHello: capture.Outer, ServerName: name, NextProtos: protocols, QUIC: capture.Transport == "quic"}
			for _, ext := range want {
				if ext.ID == 57 {
					info.QUICTransportParameters = ext.Data
				}
			}
			spec, err := policy(info)
			if err != nil {
				t.Fatal(err)
			}
			var got []extension
			for _, ext := range spec.Extensions {
				data := ext.Data
				if ext.Outer {
					found := false
					for _, source := range outer {
						if source.ID == ext.ID {
							data, found = source.Data, true
							break
						}
					}
					if !found {
						t.Fatalf("missing outer reference %d", ext.ID)
					}
				}
				got = append(got, extension{ext.ID, data})
			}
			if capture.PSK.Outer != "" {
				for _, raw := range [][]byte{capture.Outer, capture.Inner} {
					if err := echcapture.AssertRedacted(raw); err != nil {
						t.Fatal(err)
					}
				}
				// PSK framing and binders belong to the TLS engine. The
				// callback supplies the preceding browser layout only.
				for _, ext := range got {
					if ext.ID == 41 {
						t.Fatal("browser policy took ownership of engine PSK")
					}
				}
				if len(want) == 0 || want[len(want)-1].ID != 41 {
					t.Fatal("native resumed inner has no final PSK")
				}
				got = append(got, want[len(want)-1])
				if (capture.PSK.Outer == "randomized") != (spec.OuterPSK == utls.ECHOuterPSKRandomized) {
					t.Fatal("public PSK policy differs from native capture")
				}
			}
			if !reflect.DeepEqual(spec.CipherSuites, wantCiphers) {
				t.Fatalf("cipher order: %x != %x", spec.CipherSuites, wantCiphers)
			}
			if spec.OuterQUICTransportParameters != nil {
				for _, ext := range outer {
					if ext.ID == 57 && !bytes.Equal(ext.Data, spec.OuterQUICTransportParameters) {
						t.Fatal("public QUIC transport parameters differ from native capture")
					}
				}
			}
			if !reflect.DeepEqual(got, want) {
				for i := range min(len(got), len(want)) {
					if !reflect.DeepEqual(got[i], want[i]) {
						t.Errorf("extension %d: got id=%d length=%d, want id=%d length=%d", i, got[i].ID, len(got[i].Data), want[i].ID, len(want[i].Data))
					}
				}
				t.Fatalf("expanded inner differs: extension counts got=%d want=%d", len(got), len(want))
			}
		})
	}
}

func TestBrowserInnerPolicyDifferences(t *testing.T) {
	// Deliberately include padding and a future opaque extension. NSS keeps
	// padding; BoringSSL constructs its inner extensions without outer padding.
	client := utls.UClient(nil, &utls.Config{ServerName: "outer.example"}, utls.HelloCustom)
	err := client.ApplyPreset(&utls.ClientHelloSpec{CipherSuites: []uint16{0x0a0a, 0x1301, 0x1303, 0xc02f}, Extensions: []utls.TLSExtension{
		&utls.SNIExtension{}, &utls.SupportedVersionsExtension{Versions: []uint16{0x0a0a, 0x0304, 0x0303}},
		&utls.GenericExtension{Id: 0xfe0d, Data: []byte{0}}, &utls.ALPNExtension{AlpnProtocols: []string{"h2"}},
		&utls.GenericExtension{Id: 21, Data: []byte{0}}, &utls.GenericExtension{Id: 0x1234, Data: []byte{1, 2}},
		&utls.GenericExtension{Id: 23}, &utls.GenericExtension{Id: 35}, &utls.GenericExtension{Id: 65281},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		policy  utls.ECHClientHelloInnerFunc
		padding bool
	}{
		{"chrome", common.ClientHelloInner, false}, {"firefox", desktop.ClientHelloInner, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := utls.ECHClientHelloInfo{ClientHello: client.HandshakeState.Hello.Raw, ServerName: "private.example", NextProtos: []string{"http/1.1"}}
			spec, err := tc.policy(info)
			if err != nil {
				t.Fatal(err)
			}
			foundPadding, foundOpaque, foundALPN := false, false, false
			for _, ext := range spec.Extensions {
				switch ext.ID {
				case 21:
					foundPadding = true
				case 0x1234:
					foundOpaque = ext.Outer
				case 16:
					foundALPN = !ext.Outer && bytes.Equal(ext.Data, []byte{0, 9, 8, 'h', 't', 't', 'p', '/', '1', '.', '1'})
				case 23, 35, 65281:
					t.Fatalf("legacy extension %d", ext.ID)
				case 43:
					if len(ext.Data) != 5 || (tc.name == "chrome" && !bytes.Equal(ext.Data[3:], []byte{3, 4})) || (tc.name == "firefox" && !bytes.Equal(ext.Data[1:3], []byte{3, 4})) {
						t.Fatal("TLS version ordering")
					}
				}
			}
			if foundPadding != tc.padding || !foundOpaque || !foundALPN {
				t.Fatalf("padding=%v opaque=%v ALPN=%v", foundPadding, foundOpaque, foundALPN)
			}
			if tc.name == "firefox" && spec.Extensions[0].ID != 0xfe0d {
				t.Fatal("NSS inner marker must be first")
			}
			wantCiphers := 3
			if tc.name == "firefox" {
				wantCiphers = 4
			}
			if len(spec.CipherSuites) != wantCiphers || spec.CipherSuites[1] != 0x1301 || spec.CipherSuites[2] != 0x1303 || tc.name == "firefox" && spec.CipherSuites[3] != 0xc02f {
				t.Fatal("inner cipher preference changed")
			}
		})
	}
}
