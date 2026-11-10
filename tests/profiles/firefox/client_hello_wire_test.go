package firefox_test

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/enetx/surf/internal/specclone"
	"github.com/enetx/surf/profiles/firefox"
	"github.com/enetx/surf/profiles/firefox/desktop"
	"github.com/enetx/surf/tests/internal/wiretest"
	utls "github.com/refraction-networking/utls"
)

func TestFirefox160ClientHelloMatchesGolden(t *testing.T) {
	t.Parallel()
	testFirefoxHelloGolden(t, "firefox-160-windows", &firefox.HelloFirefox_160)
}

func testFirefoxHelloGolden(t *testing.T, name string, spec *utls.ClientHelloSpec) {
	t.Helper()

	fixture, err := os.ReadFile("../../testdata/wire/" + name + ".golden")
	if err != nil {
		t.Fatal(err)
	}
	_, want, found := strings.Cut(string(fixture), "## tcp client hello (h2)\n")
	if !found {
		t.Fatal("missing TLS reference")
	}
	want, _, _ = strings.Cut(want, "\n## ")
	want = strings.TrimSpace(want) + "\n"
	before := desktop.NewClientHelloSpec()
	var previousKey []byte
	for range 4 {
		conn := utls.UClient(nil, &utls.Config{
			ServerName:   "tls.peet.ws",
			OmitEmptyPsk: true,
		}, utls.HelloCustom)
		if err := conn.ApplyPreset(specclone.Clone(spec)); err != nil {
			t.Fatal(err)
		}
		if err := conn.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		got, details := wiretest.ClientHello(t, conn.HandshakeState.Hello.Raw, false)
		if got != want {
			t.Fatalf("Firefox ClientHello differs from browser capture\n got:\n%s\nwant:\n%s", got, want)
		}
		if details.ECHPayloadLength != 240 {
			t.Errorf("ECH payload = %d bytes, want 240", details.ECHPayloadLength)
		}
		if details.ECHAEAD != 1 && details.ECHAEAD != 3 {
			t.Errorf("ECH AEAD = %d, want AES-128-GCM or ChaCha20-Poly1305", details.ECHAEAD)
		}
		hybrid, classical := details.KeyShares[4588], details.KeyShares[29]
		if len(hybrid) != 1216 || len(classical) != 32 || !bytes.Equal(hybrid[len(hybrid)-32:], classical) {
			t.Fatal("Firefox must reuse the X25519 key in its hybrid and classical shares")
		}
		if bytes.Equal(previousKey, classical) {
			t.Fatal("X25519 key reused across different connections")
		}
		previousKey = bytes.Clone(classical)
	}
	if !reflect.DeepEqual(&before, spec) {
		t.Error("handshakes mutated the source Firefox TLS template")
	}
}
