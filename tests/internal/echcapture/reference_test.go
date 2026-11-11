package echcapture

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"testing"
)

// Synthetic inputs exercise validation without storing an actual usable ticket.
// Confirmation generation uses the standard HKDF implementation, independently
// of VerifyECHConfirmation's HMAC expansion.
func syntheticCapture(t *testing.T, cipher uint16) RawCapture {
	t.Helper()
	ref := nativeReferences(t)[0]
	c := RawCapture{Browser: ref.Browser, Platform: "synthetic test", Transport: ref.Transport,
		Outer: bytes.Clone(ref.Outer), Inner: bytes.Clone(ref.Inner), ServerHello: bytes.Clone(ref.ServerHello),
		EncryptedExtensions: []byte{8, 0, 0, 6, 0, 4, 0, 42, 0, 0},
		Wire:                WireEvidence{EarlyPackets: 2, EarlyControlPackets: 2, EarlyRequestPackets: 1}}
	h, _ := ReadClientHello(c.Inner)
	psk := samplePSK()
	if cipher == 0x1302 {
		psk[12], psk[13] = 49, 48
		psk = append(psk, bytes.Repeat([]byte{0x5a}, 16)...)
	}
	h.Extensions[len(h.Extensions)-1].Data = psk
	c.Inner, _ = h.Marshal()
	pos := 39 + int(c.ServerHello[38])
	binary.BigEndian.PutUint16(c.ServerHello[pos:pos+2], cipher)
	signCapture(t, &c)
	return c
}

func signCapture(t *testing.T, c *RawCapture) {
	t.Helper()
	s, err := ReadServerHello(c.ServerHello)
	if err != nil {
		t.Fatal(err)
	}
	var h func() hash.Hash = sha256.New
	if s.Cipher == 0x1302 {
		h = sha512.New384
	}
	clear(c.ServerHello[30:38])
	transcript := h()
	transcript.Write(c.Inner)
	transcript.Write(c.ServerHello)
	digest := transcript.Sum(nil)
	secret, err := hkdf.Extract(h, c.Inner[6:38], nil)
	if err != nil {
		t.Fatal(err)
	}
	label := []byte("tls13 ech accept confirmation")
	info := append([]byte{0, 8, byte(len(label))}, label...)
	info = append(info, byte(len(digest)))
	info = append(info, digest...)
	confirmation, err := hkdf.Expand(h, secret, string(info), 8)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.ServerHello[30:38], confirmation)
}

func editInner(t *testing.T, c *RawCapture, edit func(*ClientHello)) {
	t.Helper()
	h, err := ReadClientHello(c.Inner)
	if err != nil {
		t.Fatal(err)
	}
	edit(h)
	c.Inner, err = h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	signCapture(t, c)
}

func TestNewReferenceVerifiesThenRedacts(t *testing.T) {
	for _, cipher := range []uint16{0x1301, 0x1302, 0x1303} {
		c := syntheticCapture(t, cipher)
		saved := bytes.Clone(c.Inner)
		ref, err := NewReference(c)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(c.Inner, saved) || bytes.Equal(c.Inner, ref.Inner) || AssertRedacted(ref.Inner) != nil || AssertRedacted(ref.Outer) != nil {
			t.Fatal("reference leaked PSK data or modified the private capture")
		}
		if !ref.EarlyData.Accepted || ref.PSK.Selected != 0 || ref.PSK.Identities[0] != 3 {
			t.Fatal("lost authenticated resumption/early-data evidence")
		}
		// Redaction changes the transcript; its original digest is retained
		// explicitly instead of claiming the masked PSK was sent on the wire.
		c.Inner = ref.Inner
		if _, err := NewReference(c); err == nil {
			t.Fatal("accepted a masked transcript as the original handshake")
		}
	}
}

func TestNewReferenceRejectsUnprovenClaims(t *testing.T) {
	cases := map[string]func(*testing.T, *RawCapture){
		"inner framing":  func(t *testing.T, c *RawCapture) { c.Inner = c.Inner[:4] },
		"outer framing":  func(t *testing.T, c *RawCapture) { c.Outer = nil },
		"server framing": func(t *testing.T, c *RawCapture) { c.ServerHello = nil },
		"transport":      func(t *testing.T, c *RawCapture) { c.Transport = "udp" },
		"implementation": func(t *testing.T, c *RawCapture) { c.Implementation = "other" },
		"confirmation":   func(t *testing.T, c *RawCapture) { c.ServerHello[30] ^= 1 },
		"unsupported cipher": func(t *testing.T, c *RawCapture) {
			pos := 39 + int(c.ServerHello[38])
			binary.BigEndian.PutUint16(c.ServerHello[pos:pos+2], 0x1304)
		},
		"private identity leaked in outer": func(t *testing.T, c *RawCapture) {
			h, _ := ReadClientHello(c.Outer)
			h.Extensions = append(h.Extensions, Extension{1234, []byte("tkt")})
			c.Outer, _ = h.Marshal()
		},
		"outer PSK shape": func(t *testing.T, c *RawCapture) {
			h, _ := ReadClientHello(c.Outer)
			h.Extensions = append(h.Extensions, Extension{41, []byte{0}})
			c.Outer, _ = h.Marshal()
		},
		"malformed outer ECH": func(t *testing.T, c *RawCapture) {
			h, _ := ReadClientHello(c.Outer)
			for i := range h.Extensions {
				if h.Extensions[i].ID == 65037 {
					h.Extensions[i].Data = []byte{0}
				}
			}
			c.Outer, _ = h.Marshal()
		},
		"session id": func(t *testing.T, c *RawCapture) {
			editInner(t, c, func(h *ClientHello) { h.SessionID = []byte{3} })
		},
		"inner marker": func(t *testing.T, c *RawCapture) {
			editInner(t, c, func(h *ClientHello) {
				for i := range h.Extensions {
					if h.Extensions[i].ID == 65037 {
						h.Extensions[i].Data = []byte{0}
					}
				}
			})
		},
		"PSK framing": func(t *testing.T, c *RawCapture) {
			editInner(t, c, func(h *ClientHello) { h.Extensions[len(h.Extensions)-1].Data = []byte{0} })
		},
		"binder hash": func(t *testing.T, c *RawCapture) {
			pos := 39 + int(c.ServerHello[38])
			binary.BigEndian.PutUint16(c.ServerHello[pos:pos+2], 0x1302)
			signCapture(t, c)
		},
		"no early packet evidence":        func(t *testing.T, c *RawCapture) { c.Wire = WireEvidence{} },
		"negative packet count":           func(t *testing.T, c *RawCapture) { c.Wire.EarlyPackets = -1 },
		"more request packets than total": func(t *testing.T, c *RawCapture) { c.Wire.EarlyRequestPackets = 3 },
		"more control packets than total": func(t *testing.T, c *RawCapture) { c.Wire.EarlyControlPackets = 3 },
		"bad server EE framing":           func(t *testing.T, c *RawCapture) { c.EncryptedExtensions = nil },
		"nonempty early acceptance":       func(t *testing.T, c *RawCapture) { c.EncryptedExtensions = []byte{8, 0, 0, 7, 0, 5, 0, 42, 0, 1, 0} },
		"acceptance without offer": func(t *testing.T, c *RawCapture) {
			editInner(t, c, func(h *ClientHello) {
				for i, ext := range h.Extensions {
					if ext.ID == 42 {
						h.Extensions = append(h.Extensions[:i], h.Extensions[i+1:]...)
						break
					}
				}
			})
		},
		"nonempty early offer": func(t *testing.T, c *RawCapture) {
			editInner(t, c, func(h *ClientHello) {
				for i := range h.Extensions {
					if h.Extensions[i].ID == 42 {
						h.Extensions[i].Data = []byte{1}
					}
				}
			})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := syntheticCapture(t, 0x1301)
			mutate(t, &c)
			if _, err := NewReference(c); err == nil {
				t.Fatal("accepted an invalid capture")
			}
		})
	}
}

func TestReferenceDistinguishesEarlyAcceptanceFromRequestData(t *testing.T) {
	c := syntheticCapture(t, 0x1301)
	c.Wire.EarlyRequestPackets = 0
	ref, err := NewReference(c)
	if err != nil || !ref.EarlyData.Accepted || ref.EarlyData.RequestPackets != 0 {
		t.Fatal("control-only early data was confused with an early request")
	}
	c.EncryptedExtensions = []byte{8, 0, 0, 2, 0, 0}
	ref, err = NewReference(c)
	if err != nil || ref.EarlyData.Accepted {
		t.Fatal("an offer was confused with server acceptance")
	}
	outer, _ := ReadClientHello(c.Outer)
	publicPSK := samplePSK()
	copy(publicPSK[4:7], "rnd")
	outer.Extensions = append(outer.Extensions, Extension{41, publicPSK})
	c.Outer, _ = outer.Marshal()
	ref, err = NewReference(c)
	if err != nil || ref.PSK.Outer != "randomized" || AssertRedacted(ref.Outer) != nil {
		t.Fatal("invalid public PSK camouflage handling", err)
	}
}

func TestServerHelloAndConfirmationValidation(t *testing.T) {
	ref := nativeReferences(t)[0]
	inner, _ := ReadClientHello(ref.Inner)
	for n := range len(ref.ServerHello) {
		if _, err := ReadServerHello(ref.ServerHello[:n]); err == nil {
			t.Fatalf("accepted truncated server at %d", n)
		}
	}
	for _, raw := range [][]byte{nil, ref.ServerHello[:4]} {
		if err := VerifyECHConfirmation(inner.Random, raw, ref.ConfirmationHash); err == nil {
			t.Fatal("accepted malformed server")
		}
	}
	if VerifyECHConfirmation(nil, ref.ServerHello, ref.ConfirmationHash) == nil ||
		VerifyECHConfirmation(inner.Random, ref.ServerHello, nil) == nil {
		t.Fatal("accepted invalid confirmation lengths")
	}
	s, _ := ReadServerHello(ref.ServerHello)
	s.Extensions = nil
	if _, err := SelectedPSK(s); err == nil {
		t.Fatal("accepted absent server PSK selection")
	}
	if _, err := ReadEncryptedExtensions([]byte{8, 0, 0, 0}); err == nil {
		t.Fatal("accepted missing EE vector")
	}
}
