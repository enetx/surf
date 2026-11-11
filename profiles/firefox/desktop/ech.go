package desktop

import (
	"bytes"

	"github.com/enetx/surf/profiles/internal/ech"
	utls "github.com/enetx/utls"
)

// ClientHelloInner follows NSS: inner ECH marker first, private SNI and TLS 1.3
// versions next in template order, followed by the shared extension block.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13ech.c#L1352
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13con.c#L6660
func ClientHelloInner(info utls.ECHClientHelloInfo) (*utls.ECHClientHelloSpec, error) {
	ciphers, outer, err := ech.Parse(info.ClientHello)
	if err != nil {
		return nil, err
	}
	spec := &utls.ECHClientHelloSpec{CipherSuites: ciphers, Extensions: []utls.ECHClientHelloExtension{{ID: 0xfe0d, Data: []byte{1}}}}
	var compressed []utls.ECHClientHelloExtension
	for _, ext := range outer {
		inner := utls.ECHClientHelloExtension{ID: ext.ID}
		switch ext.ID {
		case 0:
			inner.Data, err = ech.ServerName(info.ServerName)
			if len(inner.Data) == 0 && err == nil {
				continue
			}
		case 43:
			inner.Data, err = ech.Versions(ext.Data, false)
		case 11, 23, 35, 41, 13172, 65281, 0xfe0d:
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
