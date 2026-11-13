package echcapture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func nativeReferences(t *testing.T) []Reference {
	return referenceFiles(t, "native", 10)
}

func referenceFiles(t *testing.T, implementation string, count int) []Reference {
	t.Helper()
	files, err := filepath.Glob("../../testdata/wire/ech/resumption/" + implementation + "/*.json")
	if err != nil || len(files) != count {
		t.Fatalf("%s references: got %d, error %v", implementation, len(files), err)
	}
	var result []Reference
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var ref Reference
		if err := json.Unmarshal(data, &ref); err != nil {
			t.Fatal(err)
		}
		result = append(result, ref)
	}
	return result
}

func TestClientHelloRoundTripAndOwnership(t *testing.T) {
	for _, ref := range nativeReferences(t) {
		for _, raw := range [][]byte{ref.Outer, ref.Inner} {
			saved := bytes.Clone(raw)
			hello, err := ReadClientHello(raw)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := hello.Marshal()
			if err != nil || !bytes.Equal(encoded, raw) {
				t.Fatal("captured handshake did not round-trip")
			}
			hello.Random[0] ^= 255
			hello.Extensions[0].Data = []byte{1, 2, 3}
			if !bytes.Equal(raw, saved) {
				t.Fatal("parser retained mutable capture storage")
			}
		}
	}
}

func TestClientHelloRejectsMalformedVectors(t *testing.T) {
	valid := nativeReferences(t)[0].Inner
	for n := range len(valid) {
		if _, err := ReadClientHello(valid[:n]); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	for _, mutate := range []func(*ClientHello){
		func(h *ClientHello) { h.SessionID = make([]byte, 33) },
		func(h *ClientHello) { h.CipherSuites = nil },
		func(h *ClientHello) { h.Compression = nil },
		func(h *ClientHello) { h.Extensions = append(h.Extensions, h.Extensions[0]) },
		func(h *ClientHello) {
			h.Extensions[0], h.Extensions[len(h.Extensions)-1] = h.Extensions[len(h.Extensions)-1], h.Extensions[0]
		},
	} {
		hello, _ := ReadClientHello(valid)
		mutate(hello)
		raw, err := hello.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadClientHello(raw); err == nil {
			t.Fatal("accepted malformed ClientHello")
		}
	}
	if _, err := ReadClientHello(append(bytes.Clone(valid), 0)); err == nil {
		t.Fatal("accepted bytes beyond the handshake")
	}
}

func samplePSK() []byte {
	// One three-byte identity, a nonzero age, and one SHA-256 binder.
	return append([]byte{0, 9, 0, 3, 't', 'k', 't', 0, 0, 0, 1, 0, 33, 32}, bytes.Repeat([]byte{0x5a}, 32)...)
}

func TestPSKRedaction(t *testing.T) {
	hello, _ := ReadClientHello(nativeReferences(t)[0].Inner)
	hello.Extensions[len(hello.Extensions)-1].Data = samplePSK()
	input, _ := hello.Marshal()
	saved := bytes.Clone(input)
	if err := AssertRedacted(input); err == nil {
		t.Fatal("accepted a live ticket as public data")
	}
	redacted, err := RedactClientHello(input)
	if err != nil || AssertRedacted(redacted) != nil || !bytes.Equal(input, saved) {
		t.Fatal("redaction failed or modified private input")
	}
	parsed, _ := ReadClientHello(redacted)
	data, _ := parsed.Extension(41)
	psk, err := ReadPSK(data)
	if err != nil || !bytes.Equal(psk.Identities[0], make([]byte, 3)) || psk.Ages[0] != 0 ||
		!bytes.Equal(psk.Binders[0], make([]byte, 32)) {
		t.Fatal("PSK fields were not fully zeroed")
	}
	before, _ := ReadClientHello(input)
	before.Extensions = before.Extensions[:len(before.Extensions)-1]
	parsed.Extensions = parsed.Extensions[:len(parsed.Extensions)-1]
	if !reflect.DeepEqual(before, parsed) || len(input) != len(redacted) {
		t.Fatal("redaction changed unrelated fields or framing")
	}
	for n := range len(samplePSK()) {
		if _, err := ReadPSK(samplePSK()[:n]); err == nil {
			t.Fatalf("accepted truncated PSK at %d", n)
		}
	}
	for _, invalid := range [][]byte{
		{0, 0, 0, 0},
		append(samplePSK(), 0),
		append(bytes.Clone(samplePSK()[:11]), 0, 0),
	} {
		if _, err := ReadPSK(invalid); err == nil {
			t.Fatal("accepted an invalid PSK vector")
		}
	}
}

func FuzzCapturedClientHello(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0})
	f.Add([]byte{1, 0, 0, 1, 0})
	data, err := os.ReadFile("../../testdata/wire/ech/resumption/native/firefox-160-quic-1.json")
	if err != nil {
		f.Fatal(err)
	}
	var ref Reference
	if err := json.Unmarshal(data, &ref); err != nil {
		f.Fatal(err)
	}
	f.Add(ref.Inner)
	f.Fuzz(func(t *testing.T, raw []byte) {
		hello, err := ReadClientHello(raw)
		if err != nil {
			return
		}
		encoded, err := hello.Marshal()
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatal("valid captured message failed round-trip")
		}
		_, _ = RedactClientHello(raw)
	})
}
