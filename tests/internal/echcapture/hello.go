// Package echcapture reads captured TLS messages without retaining live tickets
// in public reference files. It is shared by capture tools and offline tests.
package echcapture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

type Extension struct {
	ID   uint16
	Data []byte
}

type ClientHello struct {
	Version      uint16
	Random       []byte
	SessionID    []byte
	CipherSuites []uint16
	Compression  []byte
	Extensions   []Extension
}

func handshake(raw []byte, want uint8) (cryptobyte.String, error) {
	s := cryptobyte.String(raw)
	var typ uint8
	var body cryptobyte.String
	if !s.ReadUint8(&typ) || typ != want || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() {
		return nil, errors.New("invalid TLS handshake framing")
	}
	return body, nil
}

func readExtensions(s cryptobyte.String) ([]Extension, error) {
	var vector cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&vector) || !s.Empty() {
		return nil, errors.New("invalid TLS extension vector")
	}
	var extensions []Extension
	seen := make(map[uint16]bool)
	for !vector.Empty() {
		var id uint16
		var data cryptobyte.String
		if !vector.ReadUint16(&id) || !vector.ReadUint16LengthPrefixed(&data) || seen[id] {
			return nil, errors.New("truncated or duplicate TLS extension")
		}
		seen[id] = true
		extensions = append(extensions, Extension{id, bytes.Clone(data)})
	}
	return extensions, nil
}

func ReadClientHello(raw []byte) (*ClientHello, error) {
	body, err := handshake(raw, 1)
	if err != nil {
		return nil, err
	}
	hello := new(ClientHello)
	var random []byte
	var sid, ciphers, compression cryptobyte.String
	if !body.ReadUint16(&hello.Version) || !body.ReadBytes(&random, 32) ||
		!body.ReadUint8LengthPrefixed(&sid) || len(sid) > 32 ||
		!body.ReadUint16LengthPrefixed(&ciphers) || ciphers.Empty() ||
		!body.ReadUint8LengthPrefixed(&compression) || compression.Empty() {
		return nil, errors.New("invalid ClientHello fields")
	}
	hello.Random, hello.SessionID, hello.Compression = bytes.Clone(random), bytes.Clone(sid), bytes.Clone(compression)
	for !ciphers.Empty() {
		var cipher uint16
		if !ciphers.ReadUint16(&cipher) {
			return nil, errors.New("odd ClientHello cipher vector")
		}
		hello.CipherSuites = append(hello.CipherSuites, cipher)
	}
	hello.Extensions, err = readExtensions(body)
	if err != nil {
		return nil, err
	}
	for i, ext := range hello.Extensions {
		if ext.ID == 41 && i != len(hello.Extensions)-1 {
			return nil, errors.New("pre_shared_key must be the final extension")
		}
	}
	return hello, nil
}

func (h *ClientHello) Extension(id uint16) ([]byte, bool) {
	for _, ext := range h.Extensions {
		if ext.ID == id {
			return ext.Data, true
		}
	}
	return nil, false
}

func (h *ClientHello) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(1)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(h.Version)
		b.AddBytes(h.Random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(h.SessionID) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, cipher := range h.CipherSuites {
				b.AddUint16(cipher)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(h.Compression) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, ext := range h.Extensions {
				b.AddUint16(ext.ID)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ext.Data) })
			}
		})
	})
	return b.Bytes()
}

type PSK struct {
	Identities [][]byte
	Ages       []uint32
	Binders    [][]byte
}

// ReadPSK validates RFC 8446 section 4.2.11, including both nested vectors.
func ReadPSK(raw []byte) (*PSK, error) {
	s := cryptobyte.String(raw)
	var identities, binders cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&identities) || identities.Empty() ||
		!s.ReadUint16LengthPrefixed(&binders) || binders.Empty() || !s.Empty() {
		return nil, errors.New("invalid PSK vectors")
	}
	psk := new(PSK)
	for !identities.Empty() {
		var identity cryptobyte.String
		var age uint32
		if !identities.ReadUint16LengthPrefixed(&identity) || identity.Empty() || !identities.ReadUint32(&age) {
			return nil, errors.New("invalid PSK identity")
		}
		psk.Identities, psk.Ages = append(psk.Identities, bytes.Clone(identity)), append(psk.Ages, age)
	}
	for !binders.Empty() {
		var binder cryptobyte.String
		if !binders.ReadUint8LengthPrefixed(&binder) || len(binder) < 32 {
			return nil, errors.New("invalid PSK binder")
		}
		psk.Binders = append(psk.Binders, bytes.Clone(binder))
	}
	if len(psk.Identities) != len(psk.Binders) {
		return nil, errors.New("PSK identity and binder counts differ")
	}
	return psk, nil
}

// RedactClientHello zeros ticket identities, ages and binders. Framing, lengths
// and all unrelated bytes stay intact; input storage is never changed.
func RedactClientHello(raw []byte) ([]byte, error) {
	hello, err := ReadClientHello(raw)
	if err != nil {
		return nil, err
	}
	for i := range hello.Extensions {
		ext := &hello.Extensions[i]
		switch ext.ID {
		case 35:
			clear(ext.Data)
		case 41:
			psk, err := ReadPSK(ext.Data)
			if err != nil {
				return nil, err
			}
			var b cryptobyte.Builder
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, identity := range psk.Identities {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, len(identity))) })
					b.AddUint32(0)
				}
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, binder := range psk.Binders {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, len(binder))) })
				}
			})
			ext.Data, err = b.Bytes()
			if err != nil {
				return nil, err
			}
		}
	}
	return hello.Marshal()
}

func AssertRedacted(raw []byte) error {
	hello, err := ReadClientHello(raw)
	if err != nil {
		return err
	}
	if data, _ := hello.Extension(35); slices.ContainsFunc(data, func(b byte) bool { return b != 0 }) {
		return errors.New("reference retains a legacy session ticket")
	}
	if data, present := hello.Extension(41); present {
		psk, err := ReadPSK(data)
		if err != nil {
			return err
		}
		for i := range psk.Identities {
			if psk.Ages[i] != 0 || slices.ContainsFunc(psk.Identities[i], func(b byte) bool { return b != 0 }) ||
				slices.ContainsFunc(psk.Binders[i], func(b byte) bool { return b != 0 }) {
				return errors.New("reference retains private PSK data")
			}
		}
	}
	return nil
}

type ServerHello struct {
	Random     []byte
	SessionID  []byte
	Cipher     uint16
	Extensions []Extension
}

func ReadServerHello(raw []byte) (*ServerHello, error) {
	body, err := handshake(raw, 2)
	if err != nil {
		return nil, err
	}
	var version uint16
	var random []byte
	var sid cryptobyte.String
	var compression uint8
	server := new(ServerHello)
	if !body.ReadUint16(&version) || !body.ReadBytes(&random, 32) || !body.ReadUint8LengthPrefixed(&sid) || len(sid) > 32 ||
		!body.ReadUint16(&server.Cipher) || !body.ReadUint8(&compression) || version != 0x0303 || compression != 0 {
		return nil, errors.New("invalid TLS 1.3 ServerHello")
	}
	server.Random = bytes.Clone(random)
	server.SessionID = bytes.Clone(sid)
	server.Extensions, err = readExtensions(body)
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (h *ServerHello) Extension(id uint16) ([]byte, bool) {
	for _, ext := range h.Extensions {
		if ext.ID == id {
			return ext.Data, true
		}
	}
	return nil, false
}

func ReadEncryptedExtensions(raw []byte) ([]Extension, error) {
	body, err := handshake(raw, 8)
	if err != nil {
		return nil, err
	}
	return readExtensions(body)
}

func PSKLengths(psk *PSK) (identities, binders []int) {
	for _, identity := range psk.Identities {
		identities = append(identities, len(identity))
	}
	for _, binder := range psk.Binders {
		binders = append(binders, len(binder))
	}
	return identities, binders
}

func SelectedPSK(server *ServerHello) (int, error) {
	data, _ := server.Extension(41)
	if len(data) != 2 {
		return 0, errors.New("ServerHello did not select a PSK identity")
	}
	return int(binary.BigEndian.Uint16(data)), nil
}
