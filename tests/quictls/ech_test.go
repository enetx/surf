package quictls_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"testing"

	"github.com/enetx/surf/internal/quictls"
	"github.com/enetx/surf/profiles/chrome/common"
	chrome "github.com/enetx/surf/profiles/chrome/quic"
	"github.com/enetx/surf/profiles/firefox/desktop"
	firefox "github.com/enetx/surf/profiles/firefox/quic"
	u "github.com/enetx/utls"
	"golang.org/x/crypto/cryptobyte"
)

func adapterECHConfig(t *testing.T) ([]byte, tls.EncryptedClientHelloKey) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1)
		b.AddUint16(0x20)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
		b.AddUint8(32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.example")) })
		b.AddUint16(0)
	})
	config := b.BytesOrPanic()
	list := cryptobyte.NewBuilder(nil)
	list.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(config) })
	return list.BytesOrPanic(), tls.EncryptedClientHelloKey{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}
}

func TestECHQUICEarlySecretsAndResumption(t *testing.T) {
	for _, browser := range []struct {
		name  string
		spec  func() (u.ClientHelloSpec, error)
		inner u.ECHClientHelloInnerFunc
	}{
		{"chrome", chrome.NewClientHelloSpec, common.ClientHelloInner},
		{"firefox", firefox.NewClientHelloSpec, desktop.ClientHelloInner},
	} {
		for _, mode := range []string{"accepted", "hrr", "alpn-changed", "application-rejected"} {
			t.Run(browser.name+"/"+mode, func(t *testing.T) {
				cc, sc := configs(t)
				list, key := adapterECHConfig(t)
				cc.EncryptedClientHelloConfigList = list
				sc.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{key}
				cc.ClientSessionCache = tls.NewLRUClientSessionCache(4)
				factory := quictls.Factory(browser.spec, browser.inner)
				first, err := drive(t, factory, cc, sc, true)
				if err != nil || first.resumed || len(first.earlyWrite) != 0 {
					t.Fatalf("first handshake: resumed=%t early=%t error=%v", first.resumed, len(first.earlyWrite) > 0, err)
				}
				if mode == "hrr" {
					sc.CurvePreferences = []tls.CurveID{tls.CurveP384}
				}
				if mode == "alpn-changed" {
					cc.NextProtos = []string{"h3-test"}
					sc.NextProtos = cc.NextProtos
				}
				resumed, err := drive(t, factory, cc, sc, mode != "application-rejected")
				if err != nil || !resumed.resumed || !resumed.extra {
					t.Fatalf("resumption: resumed=%t metadata=%t error=%v", resumed.resumed, resumed.extra, err)
				}
				if mode == "accepted" {
					if len(resumed.earlyWrite) == 0 || !bytes.Equal(resumed.earlyWrite, resumed.earlyRead) {
						t.Fatal("client/server ECH early traffic secrets differ")
					}
				} else if mode == "hrr" {
					if !resumed.hrr || !resumed.rejectedEarly || len(resumed.earlyRead) != 0 {
						t.Fatal("HRR did not reject 0-RTT before resuming")
					}
				} else if len(resumed.earlyWrite) != 0 || len(resumed.earlyRead) != 0 {
					t.Fatal("ineligible session enabled 0-RTT")
				}
			})
		}
	}
}
