package chrome_test

import (
	"os"
	"strings"
	"testing"

	"github.com/enetx/surf/internal/specclone"
	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/tests/internal/wiretest"
	utls "github.com/refraction-networking/utls"
)

// Each platform has a separate normalized wire reference.
// See ../../testdata/wire/README.md for normalization rules.
// Random GREASE values, key material, ECH and extension permutations are normalized
// for comparison with the fixture. The endpoint uses an IP, so it has no SNI.
func TestChromeClientHelloMatchesGolden(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		spec    *utls.ClientHelloSpec
		shuffle bool
	}{
		{"chrome-157-windows", &chrome.HelloChrome_157, true},
		{"chrome-157-android", &chrome.HelloChrome_157_Mobile, true},
		{"chrome-157-ios", chrome.IOS.HelloSpec, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, err := os.ReadFile("../../testdata/wire/" + tc.name + ".golden")
			if err != nil {
				t.Fatal(err)
			}
			_, want, found := strings.Cut(string(fixture), "## tcp client hello (h2)\n")
			if !found {
				t.Fatal("missing TLS reference")
			}
			want, _, _ = strings.Cut(want, "\n## ")
			want = strings.TrimSpace(want) + "\n"
			greases := make(map[uint16]bool)
			for range 16 {
				serverName := "127.0.0.1"
				if tc.name == "chrome-157-ios" {
					serverName = "tls.peet.ws"
				}
				conn := utls.UClient(nil, &utls.Config{
					ServerName:   serverName,
					OmitEmptyPsk: true,
				}, utls.HelloCustom)
				if err := conn.ApplyPreset(specclone.Clone(tc.spec)); err != nil {
					t.Fatal(err)
				}
				if err := conn.BuildHandshakeState(); err != nil {
					t.Fatal(err)
				}
				got, details := wiretest.ClientHello(t, conn.HandshakeState.Hello.Raw, tc.shuffle)
				if got != want {
					t.Fatalf("ClientHello differs from platform reference\n got:\n%s\nwant:\n%s", got, want)
				}
				greases[details.SignatureGREASE] = true
			}
			if tc.shuffle && len(greases) < 2 {
				t.Error("signature_algorithms GREASE did not vary across connections")
			}
		})
	}
}
