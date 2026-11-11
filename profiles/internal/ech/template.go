// Package ech contains wire helpers shared by browser-owned ECH policies.
package ech

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"

	utls "github.com/enetx/utls"
)

type Extension struct {
	ID   uint16
	Data []byte
}

func Grease(id uint16) bool { return id&0x0f0f == 0x0a0a && byte(id>>8) == byte(id) }

// Parse reads the serialized template without losing extensions unknown to Go.
func Parse(raw []byte) ([]uint16, []Extension, error) {
	fail := func() ([]uint16, []Extension, error) { return nil, nil, errors.New("invalid ECH outer template") }
	if len(raw) < 39 || raw[0] != 1 || int(raw[1])<<16|int(raw[2])<<8|int(raw[3]) != len(raw)-4 {
		return fail()
	}
	i := 38
	i += 1 + int(raw[i])
	if i+2 > len(raw) {
		return fail()
	}
	n := int(binary.BigEndian.Uint16(raw[i:]))
	i += 2
	if n%2 != 0 || i+n >= len(raw) {
		return fail()
	}
	var ciphers []uint16
	for end := i + n; i < end; i += 2 {
		id := binary.BigEndian.Uint16(raw[i:])
		if Grease(id) || id >= 0x1301 && id <= 0x1305 {
			ciphers = append(ciphers, id)
		}
	}
	i += 1 + int(raw[i])
	if i+2 > len(raw) {
		return fail()
	}
	n = int(binary.BigEndian.Uint16(raw[i:]))
	i += 2
	if i+n != len(raw) {
		return fail()
	}
	var extensions []Extension
	for i < len(raw) {
		if i+4 > len(raw) {
			return fail()
		}
		id, size := binary.BigEndian.Uint16(raw[i:]), int(binary.BigEndian.Uint16(raw[i+2:]))
		i += 4
		if i+size > len(raw) {
			return fail()
		}
		extensions = append(extensions, Extension{id, raw[i : i+size]})
		i += size
	}
	return ciphers, extensions, nil
}

func ServerName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if net.ParseIP(strings.Trim(name, "[]")) != nil || name == "" {
		return nil, nil
	}
	if len(name) > 65530 {
		return nil, errors.New("ECH server name too long")
	}
	out := make([]byte, 5+len(name))
	binary.BigEndian.PutUint16(out, uint16(len(name)+3))
	binary.BigEndian.PutUint16(out[3:], uint16(len(name)))
	copy(out[5:], name)
	return out, nil
}

func Versions(data []byte, greaseFirst bool) ([]byte, error) {
	if len(data) < 3 || int(data[0]) != len(data)-1 || len(data)%2 != 1 {
		return nil, errors.New("invalid ECH supported versions")
	}
	var grease []uint16
	for i := 1; i < len(data); i += 2 {
		id := binary.BigEndian.Uint16(data[i:])
		if Grease(id) {
			grease = append(grease, id)
		}
	}
	values := []uint16{utls.VersionTLS13}
	if greaseFirst {
		values = append(grease, values...)
	} else {
		values = append(values, grease...)
	}
	out := make([]byte, 1+2*len(values))
	out[0] = byte(len(out) - 1)
	for i, v := range values {
		binary.BigEndian.PutUint16(out[1+2*i:], v)
	}
	return out, nil
}

func ALPN(protocols []string) ([]byte, error) {
	n := 0
	for _, p := range protocols {
		if len(p) == 0 || len(p) > 255 {
			return nil, errors.New("invalid ECH ALPN protocol")
		}
		n += 1 + len(p)
	}
	if n > 65533 {
		return nil, errors.New("ECH ALPN list too long")
	}
	out := make([]byte, 2, n+2)
	binary.BigEndian.PutUint16(out, uint16(n))
	for _, p := range protocols {
		out = append(out, byte(len(p)))
		out = append(out, p...)
	}
	return out, nil
}
