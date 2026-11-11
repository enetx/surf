package echcapture

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestNativeResumptionReferences(t *testing.T) {
	seen := make(map[string]int)
	canonical := make(map[string]*Fingerprint)
	for _, ref := range nativeReferences(t) {
		t.Run(ref.Browser+"/"+ref.Transport, func(t *testing.T) {
			if ref.Schema != 1 || ref.Implementation != "native" {
				t.Fatal("fixture is not a native reference")
			}
			if err := AssertRedacted(ref.Outer); err != nil {
				t.Fatal(err)
			}
			if err := AssertRedacted(ref.Inner); err != nil {
				t.Fatal(err)
			}
			inner, err := ReadClientHello(ref.Inner)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyECHConfirmation(inner.Random, ref.ServerHello, ref.ConfirmationHash); err != nil {
				t.Fatal(err)
			}
			bad := bytes.Clone(ref.ConfirmationHash)
			bad[0] ^= 1
			if err := VerifyECHConfirmation(inner.Random, ref.ServerHello, bad); err == nil {
				t.Fatal("accepted a different private transcript")
			}
			pskData, _ := inner.Extension(41)
			psk, err := ReadPSK(pskData)
			if err != nil {
				t.Fatal(err)
			}
			identities, binders := PSKLengths(psk)
			if !slices.Equal(identities, ref.PSK.Identities) || !slices.Equal(binders, ref.PSK.Binders) {
				t.Fatal("redaction changed the recorded PSK shape")
			}
			_, offered := inner.Extension(42)
			if offered != ref.EarlyData.Offered || ref.EarlyData.Accepted != slices.Contains(ref.ServerExtensions, 42) ||
				ref.EarlyData.Accepted && ref.EarlyData.Packets == 0 {
				t.Fatal("early-data claim has no handshake/packet evidence")
			}
			family := strings.ToLower(strings.Split(ref.Browser, "/")[0])
			if family == "chrome" && ref.PSK.Outer != "omitted" || family == "firefox" && ref.PSK.Outer != "randomized" {
				t.Fatal("native public PSK policy changed")
			}
			seen[family+"/"+ref.Transport]++
			fp, err := StableFingerprint(ref.Inner, family, ref.Transport)
			if err != nil {
				t.Fatal(err)
			}
			key := family + "/" + ref.Transport
			if previous := canonical[key]; previous != nil && !reflect.DeepEqual(previous, fp) {
				t.Fatalf("native stable features differ: %v / %v", previous, fp)
			}
			canonical[key] = fp
		})
	}
	for _, pair := range []string{"chrome/tcp", "chrome/quic", "firefox/tcp", "firefox/quic"} {
		if seen[pair] == 0 {
			t.Fatalf("missing native scenario %s", pair)
		}
	}
}

func TestFingerprintKeepsMeaningfulDifferences(t *testing.T) {
	ref := nativeReferences(t)[0]
	base, err := StableFingerprint(ref.Inner, "chrome", ref.Transport)
	if err != nil {
		t.Fatal(err)
	}
	hello, _ := ReadClientHello(ref.Inner)
	hello.Random[0] ^= 1
	hello.SessionID = bytes.Repeat([]byte{3}, len(hello.SessionID))
	for i := range hello.CipherSuites {
		if IsGREASE(hello.CipherSuites[i]) {
			hello.CipherSuites[i] = 0xaaaa
		}
	}
	raw, _ := hello.Marshal()
	got, err := StableFingerprint(raw, "chrome", ref.Transport)
	if err != nil || !reflect.DeepEqual(base, got) {
		t.Fatal("connection randomness changed the stable fingerprint")
	}
	hello.CipherSuites[1] = 0x1304
	raw, _ = hello.Marshal()
	got, err = StableFingerprint(raw, "chrome", ref.Transport)
	if err != nil || reflect.DeepEqual(base, got) {
		t.Fatal("cipher changes disappeared during normalization")
	}
	if _, err := StableFingerprint(ref.Inner, "other", ref.Transport); err == nil {
		t.Fatal("accepted an unspecified permutation policy")
	}
}
