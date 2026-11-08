package quictls_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/enetx/quic-go/tlsquic"
	"github.com/enetx/surf/internal/quictls"
	u "github.com/refraction-networking/utls"
)

func configs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: u.VersionTLS13, NextProtos: []string{"h3"}, ClientSessionCache: tls.NewLRUClientSessionCache(4)}, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func spec(t *testing.T, id u.ClientHelloID) *u.ClientHelloSpec {
	t.Helper()
	s, err := u.UTLSIdToSpec(id)
	if err != nil {
		t.Fatal(err)
	}
	s.TLSVersMin = u.VersionTLS13
	s.TLSVersMax = u.VersionTLS13
	ciphers := s.CipherSuites[:0]
	for _, c := range s.CipherSuites {
		if c == 0x1301 || c == 0x1302 || c == 0x1303 || c == u.GREASE_PLACEHOLDER {
			ciphers = append(ciphers, c)
		}
	}
	s.CipherSuites = ciphers
	exts := make([]u.TLSExtension, 0, len(s.Extensions)+2)
	for _, ext := range s.Extensions {
		switch e := ext.(type) {
		case *u.RenegotiationInfoExtension, *u.SessionTicketExtension, *u.SupportedPointsExtension, *u.ExtendedMasterSecretExtension, *u.UtlsPaddingExtension:
			continue
		case *u.ALPNExtension:
			e.AlpnProtocols = []string{"h3"}
		case *u.SupportedVersionsExtension:
			e.Versions = []uint16{u.VersionTLS13}
		}
		exts = append(exts, ext)
	}
	hasModes := false
	for _, e := range exts {
		if _, ok := e.(*u.PSKKeyExchangeModesExtension); ok {
			hasModes = true
		}
	}
	if !hasModes {
		exts = append(exts, &u.PSKKeyExchangeModesExtension{Modes: []uint8{u.PskModeDHE}})
	}
	s.Extensions = append(exts, &u.QUICTransportParametersExtension{}, &u.UtlsPreSharedKeyExtension{})
	return &s
}

type observed struct {
	clientParams, serverParams, hello []byte
	resumed                           bool
	extra                             bool
}

func drive(t *testing.T, factory tlsquic.NewClient, cc, sc *tls.Config) (observed, error) {
	t.Helper()
	cli, err := factory(cc)
	if err != nil {
		return observed{}, err
	}
	defer cli.Close()
	clientParams := []byte{0x0f, 0, 0x04, 1, 0x10, 0x27, 1, 0x03}
	serverParams := []byte{0x0f, 1, 0xab}
	cli.SetTransportParameters(clientParams)
	srv := tls.QUICServer(&tls.QUICConfig{TLSConfig: sc, EnableSessionEvents: true})
	defer srv.Close()
	srv.SetTransportParameters(serverParams)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cli.Start(ctx); err != nil {
		return observed{}, err
	}
	if err := srv.Start(ctx); err != nil {
		return observed{}, err
	}
	out := observed{}
	clientDone, serverDone := false, false
	for n := 0; n < 1000; n++ {
		progress := false
		for _, side := range []bool{true, false} {
			for {
				var e tls.QUICEvent
				if side {
					e = cli.NextEvent()
				} else {
					e = srv.NextEvent()
				}
				if e.Kind == tls.QUICNoEvent {
					break
				}
				progress = true
				switch e.Kind {
				case tls.QUICWriteData:
					if side {
						if e.Level == tls.QUICEncryptionLevelInitial {
							out.hello = append(out.hello, e.Data...)
						}
						err = srv.HandleData(e.Level, e.Data)
					} else {
						err = cli.HandleData(e.Level, e.Data)
					}
					if err != nil {
						return out, err
					}
				case tls.QUICTransportParameters:
					if side {
						out.serverParams = bytes.Clone(e.Data)
					} else {
						out.clientParams = bytes.Clone(e.Data)
					}
				case tls.QUICHandshakeDone:
					if side {
						clientDone = true
					} else {
						serverDone = true
						if err := srv.SendSessionTicket(tls.QUICSessionTicketOptions{EarlyData: true}); err != nil {
							return out, err
						}
					}
				case tls.QUICStoreSession:
					e.SessionState.Extra = append(e.SessionState.Extra, []byte("quic-state"))
					if err := cli.StoreSession(e.SessionState); err != nil {
						return out, err
					}
				case tls.QUICResumeSession:
					if side {
						out.extra = len(e.SessionState.Extra) > 0 && bytes.Equal(e.SessionState.Extra[len(e.SessionState.Extra)-1], []byte("quic-state"))
						e.SessionState.EarlyData = false
					}
				case tls.QUICSetWriteSecret:
					if side && e.Level == tls.QUICEncryptionLevelEarly {
						return out, errors.New("EarlyData edit lost between events")
					}
				case tls.QUICErrorEvent:
					return out, e.Err
				}
			}
		}
		if !progress {
			if !clientDone || !serverDone {
				return out, fmt.Errorf("incomplete handshake")
			}
			out.resumed = cli.ConnectionState().DidResume
			return out, nil
		}
	}
	return out, fmt.Errorf("event limit")
}
func extension(hello []byte, id uint16) ([]byte, error) {
	if len(hello) < 39 {
		return nil, fmt.Errorf("short hello")
	}
	b := hello[38:]
	if int(b[0]) != 0 {
		return nil, fmt.Errorf("QUIC legacy session ID is nonzero")
	}
	b = b[1:]
	l := int(binary.BigEndian.Uint16(b))
	b = b[2+l:]
	l = int(b[0])
	b = b[1+l:]
	l = int(binary.BigEndian.Uint16(b))
	b = b[2 : 2+l]
	for len(b) >= 4 {
		i, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if n > len(b) {
			return nil, fmt.Errorf("bad extension")
		}
		if i == id {
			return b[:n], nil
		}
		b = b[n:]
	}
	return nil, fmt.Errorf("missing extension %d", id)
}
func TestOfficialUQUIC(t *testing.T) {
	for _, id := range []u.ClientHelloID{u.HelloChrome_155, u.HelloFirefox_148} {
		t.Run(id.Str(), func(t *testing.T) {
			cc, sc := configs(t)
			verified := 0
			cc.VerifyConnection = func(state tls.ConnectionState) error {
				if len(state.VerifiedChains) == 0 {
					return errors.New("certificate chain not verified")
				}
				verified++
				return nil
			}
			factory := quictls.Factory(func() (u.ClientHelloSpec, error) { return *spec(t, id), nil })
			for i := 0; i < 2; i++ {
				got, err := drive(t, factory, cc, sc)
				if err != nil {
					t.Fatal(err)
				}
				if got.resumed != (i == 1) {
					t.Fatalf("resumed=%t round=%d", got.resumed, i)
				}
				if i == 1 && !got.extra {
					t.Fatal("session metadata lost")
				}
				if !bytes.Equal(got.clientParams, []byte{0x0f, 0, 0x04, 1, 0x10, 0x27, 1, 0x03}) {
					t.Fatalf("peer parameters=%x", got.clientParams)
				}
				tp, err := extension(got.hello, 57)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(tp, got.clientParams) {
					t.Fatal("TP differ on wire")
				}
			}
			if verified != 2 {
				t.Fatalf("verification callback called %d times", verified)
			}
			bad := cc.Clone()
			bad.ServerName = "wrong.example"
			bad.ClientSessionCache = nil
			if _, err := drive(t, factory, bad, sc); err == nil {
				t.Fatal("invalid certificate accepted")
			}
		})
	}
}
func TestInvalidTemplatesAndCallbacks(t *testing.T) {
	config, _ := configs(t)
	for _, template := range []u.ClientHelloSpec{{}, {Extensions: []u.TLSExtension{&u.ALPNExtension{AlpnProtocols: []string{"h3"}}}}} {
		factory := quictls.Factory(func() (u.ClientHelloSpec, error) { return template, nil })
		if _, err := factory(config); err == nil {
			t.Fatal("TCP/empty template accepted")
		}
	}
	sentinel := errors.New("bad template")
	if _, err := quictls.Factory(func() (u.ClientHelloSpec, error) { return u.ClientHelloSpec{}, sentinel })(config); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, nil }
	if _, err := quictls.Factory(func() (u.ClientHelloSpec, error) { return *spec(t, u.HelloChrome_155), nil })(config); err == nil {
		t.Fatal("unsupported callback silently dropped")
	}
}
