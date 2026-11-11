package common

import (
	"bytes"

	"github.com/enetx/surf/profiles/internal/ech"
	utls "github.com/enetx/utls"
)

// ClientHelloInner follows the ECH extension permutation and contiguous outer
// references in Chrome 157's pinned BoringSSL. TLS 1.2-only fields are omitted.
// https://github.com/google/boringssl/blob/5b83e5d1abf0ae0033ae52ab579d906b67633b2c/ssl/extensions.cc#L4379
// https://github.com/google/boringssl/blob/5b83e5d1abf0ae0033ae52ab579d906b67633b2c/ssl/handshake_client.cc#L86
func ClientHelloInner(info utls.ECHClientHelloInfo) (*utls.ECHClientHelloSpec, error) {
	ciphers, outer, err := ech.Parse(info.ClientHello)
	if err != nil {
		return nil, err
	}
	spec := &utls.ECHClientHelloSpec{CipherSuites: ciphers}
	var compressed []utls.ECHClientHelloExtension
	for _, ext := range outer {
		inner := utls.ECHClientHelloExtension{ID: ext.ID}
		switch ext.ID {
		case 0:
			inner.Data, err = ech.ServerName(info.ServerName)
			if len(inner.Data) == 0 && err == nil {
				continue
			}
		case 0xfe0d:
			inner.Data = []byte{1}
		case 43:
			inner.Data, err = ech.Versions(ext.Data, true)
		case 11, 21, 23, 35, 41, 13172, 65281:
			continue
		default:
			if ext.ID == 16 && len(info.NextProtos) > 0 {
				inner.Data, err = ech.ALPN(info.NextProtos)
				if err != nil {
					return nil, err
				}
				if err == nil && !bytes.Equal(inner.Data, ext.Data) {
					spec.Extensions = append(spec.Extensions, inner)
					continue
				}
			}
			compressed = append(compressed, utls.ECHClientHelloExtension{ID: ext.ID, Outer: true})
			continue
		}
		if err != nil {
			return nil, err
		}
		spec.Extensions = append(spec.Extensions, inner)
	}
	spec.Extensions = append(spec.Extensions, compressed...)
	return spec, nil
}
