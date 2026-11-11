package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enetx/surf/tests/internal/echcapture"
)

func TestCompareCapturedInner(t *testing.T) {
	path := "../../testdata/wire/ech/resumption/native/chrome-157-tcp-1.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ref echcapture.Reference
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	keylog := filepath.Join(t.TempDir(), "keys.log")
	line := "UTLS_ECH_INNER_CLIENT_HELLO " + strings.Repeat("ab", 32) + " " + hex.EncodeToString(ref.Inner) + "\n"
	if err := os.WriteFile(keylog, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if err := compare(keylog, path, 1); err != nil {
		t.Fatal(err)
	}
	for _, record := range []int{0, -1, 2} {
		if err := compare(keylog, path, record); err == nil {
			t.Fatal("accepted invalid record index")
		}
	}
	h, _ := echcapture.ReadClientHello(ref.Inner)
	h.CipherSuites[1] ^= 1
	changed, _ := h.Marshal()
	if err := os.WriteFile(keylog, []byte(strings.Replace(line, hex.EncodeToString(ref.Inner), hex.EncodeToString(changed), 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := compare(keylog, path, 1); err == nil {
		t.Fatal("hid a cipher regression")
	}
}

func TestReferenceInputValidationDoesNotWrite(t *testing.T) {
	for _, input := range []string{"[]", "{}", "[{}]", "[] {}", "[{\"unexpected\":1}]"} {
		dir := t.TempDir()
		path, out := filepath.Join(dir, "private.json"), filepath.Join(dir, "public")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if err := references(path, out); err == nil {
			t.Fatal("accepted invalid private capture")
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("invalid capture produced output")
		}
	}
	if references("", "") == nil || references("missing", "unused") == nil {
		t.Fatal("accepted missing input")
	}
}

func TestProbeRejectsInvalidOptionsBeforeOpeningLog(t *testing.T) {
	for _, tc := range []struct {
		browser, protocol string
		early, racing     bool
	}{
		{"other", "h3", false, false}, {"chrome", "h1", false, false}, {"firefox", "h2", true, false}, {"chrome", "h2", false, true},
	} {
		path := filepath.Join(t.TempDir(), "private.keys")
		if err := probe(tc.browser, tc.protocol, path, tc.early, tc.racing); err == nil {
			t.Fatal("accepted invalid probe options")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("opened log before validating options")
		}
	}
	if err := probe("chrome", "h3", "", false, false); err == nil {
		t.Fatal("accepted missing key log")
	}
	path := filepath.Join(t.TempDir(), "existing.keys")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := probe("chrome", "h3", path, false, false); err == nil {
		t.Fatal("overwrote an existing key log")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "keep" {
		t.Fatal("changed existing capture")
	}
}
