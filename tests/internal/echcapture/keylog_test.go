package echcapture

import (
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

func TestReadInnerKeyLog(t *testing.T) {
	raw := nativeReferences(t)[0].Inner
	line := "UTLS_ECH_INNER_CLIENT_HELLO " + strings.Repeat("ab", 32) + " " + hex.EncodeToString(raw) + "\n"
	records, err := ReadInnerKeyLog(strings.NewReader("# standard log\nCLIENT_RANDOM unused ignored\n" + line + line))
	if err != nil || len(records) != 2 || len(records[0].OuterRandom) != 32 || hex.EncodeToString(records[0].Inner) != hex.EncodeToString(raw) {
		t.Fatal("lost repeated/HRR records or parsed an unrelated traffic-secret label")
	}
	for _, invalid := range []string{
		"UTLS_ECH_INNER_CLIENT_HELLO", "UTLS_ECH_INNER_CLIENT_HELLO ab 00",
		"UTLS_ECH_INNER_CLIENT_HELLO " + strings.Repeat("ab", 32) + " zz",
		"UTLS_ECH_INNER_CLIENT_HELLO " + strings.Repeat("ab", 32) + " 01000000",
		strings.TrimSpace(line) + " extra", strings.Repeat("x", (1<<20)+1),
	} {
		if _, err := ReadInnerKeyLog(strings.NewReader(invalid)); err == nil {
			t.Fatal("accepted a malformed capture line")
		}
	}
	if _, err := ReadInnerKeyLog(io.MultiReader(strings.NewReader(line), failingReader{})); err == nil {
		t.Fatal("lost reader failure")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
