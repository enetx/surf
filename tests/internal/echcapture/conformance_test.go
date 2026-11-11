package echcapture

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestSurfResumptionWireReferences(t *testing.T) {
	native := make(map[string]Reference)
	for _, ref := range nativeReferences(t) {
		native[ref.Browser+"/"+ref.Transport] = ref
	}
	for _, ref := range referenceFiles(t, "surf", 4) {
		t.Run(ref.Browser+"/"+ref.Transport, func(t *testing.T) {
			want, ok := native[ref.Browser+"/"+ref.Transport]
			if !ok || ref.Implementation != "surf" || ref.Schema != 1 {
				t.Fatal("missing native comparison")
			}
			for _, raw := range [][]byte{ref.Inner, ref.Outer} {
				if err := AssertRedacted(raw); err != nil {
					t.Fatal(err)
				}
			}
			h, _ := ReadClientHello(ref.Inner)
			if err := VerifyECHConfirmation(h.Random, ref.ServerHello, ref.ConfirmationHash); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ref.PSK, want.PSK) {
				t.Fatal("Surf/native resumption framing or outer PSK privacy differs")
			}
			if ref.Transport == "quic" && (!ref.EarlyData.Offered || !ref.EarlyData.Accepted || ref.EarlyData.RequestPackets < 1) {
				t.Fatal("Surf early request has no authenticated handshake/decrypted packet evidence")
			}
			if ref.Transport == "tcp" && (ref.EarlyData.Offered || ref.EarlyData.Accepted || ref.EarlyData.Packets != 0) {
				t.Fatal("unexpected TCP early data")
			}
			family := strings.ToLower(strings.Split(ref.Browser, "/")[0])
			a, err := StableFingerprint(want.Inner, family, ref.Transport)
			if err != nil {
				t.Fatal(err)
			}
			b, err := StableFingerprint(ref.Inner, family, ref.Transport)
			if err != nil {
				t.Fatal(err)
			}
			if family == "chrome" && ref.Transport == "quic" {
				// Explicitly document the one measured gap instead of hiding it
				// in the generic normalizer. Network-history RTT hints are a
				// separate feature; this phase establishes honest references.
				removed := false
				for i := range a.Extensions {
					if a.Extensions[i].ID != "57" {
						continue
					}
					values := strings.Split(a.Extensions[i].Value, ";")
					values = slices.DeleteFunc(values, func(value string) bool {
						if strings.HasPrefix(value, "12583/") {
							removed = true
							return true
						}
						return false
					})
					a.Extensions[i].Value = strings.Join(values, ";")
				}
				if !removed {
					t.Fatal("native RTT hint disappeared from the reference")
				}
			}
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("unexpected stable inner difference:\nnative=%v\nsurf=%v", a, b)
			}
		})
	}
}
