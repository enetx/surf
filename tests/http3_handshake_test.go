package surf_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/transportparams"
	"github.com/enetx/surf"
	u "github.com/refraction-networking/utls"
)

// Independent RFC 9001 Initial decoder. These checks observe actual UDP bytes,
// rather than trusting the client configuration or its trace records.
func h3InitialPlaintext(packet []byte, initialDCID []byte) ([]byte, uint64, error) {
	b := bytes.Clone(packet)
	if len(b) < 7 || b[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(b[1:5]) != 1 {
		return nil, 0, errors.New("not QUIC v1 Initial")
	}
	p := 6 + int(b[5])
	if p >= len(b) {
		return nil, 0, errors.New("short destination ID")
	}
	dcid := initialDCID
	if len(dcid) == 0 {
		dcid = b[6:p]
	}
	p += 1 + int(b[p])
	if p >= len(b) {
		return nil, 0, errors.New("short source ID")
	}
	token, n, err := quicvarint.Parse(b[p:])
	if err != nil {
		return nil, 0, err
	}
	p += n
	if token > uint64(len(b)-p) {
		return nil, 0, errors.New("short token")
	}
	p += int(token)
	length, n, err := quicvarint.Parse(b[p:])
	if err != nil {
		return nil, 0, err
	}
	p += n
	if length > uint64(len(b)-p) || p+20 > len(b) {
		return nil, 0, errors.New("short payload")
	}
	end := p + int(length)
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, 0, err
	}
	expand := func(secret []byte, label string, n int) []byte {
		full := "tls13 " + label
		info := binary.BigEndian.AppendUint16(nil, uint16(n))
		info = append(info, byte(len(full)))
		info = append(info, full...)
		info = append(info, 0)
		out, err := hkdf.Expand(sha256.New, secret, string(info), n)
		if err != nil {
			panic(err)
		}
		return out
	}
	secret := expand(initial, "client in", 32)
	hp, err := aes.NewCipher(expand(secret, "quic hp", 16))
	if err != nil {
		return nil, 0, err
	}
	var mask [16]byte
	hp.Encrypt(mask[:], b[p+4:p+20])
	b[0] ^= mask[0] & 15
	pnLen := int(b[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		b[p+i] ^= mask[i+1]
		pn = pn<<8 | uint64(b[p+i])
	}
	block, err := aes.NewCipher(expand(secret, "quic key", 16))
	if err != nil {
		return nil, 0, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	nonce := expand(secret, "quic iv", 12)
	number := binary.BigEndian.AppendUint64(nil, pn)
	for i, v := range number {
		nonce[len(nonce)-8+i] ^= v
	}
	header := b[:p+pnLen]
	payload, err := aead.Open(nil, nonce, b[p+pnLen:end], header)
	return payload, pn, err
}
func h3CapturedHello(t *testing.T, peer *h3Peer) ([]byte, uint64) {
	t.Helper()
	peer.packet.mu.Lock()
	packets := slices.Clone(peer.packet.rawInitials)
	peer.packet.mu.Unlock()
	data := make([]byte, 1<<16)
	present := make([]bool, len(data))
	var firstPN uint64
	var initialDCID []byte
	if len(packets) > 0 {
		initialDCID = bytes.Clone(packets[0][6 : 6+int(packets[0][5])])
	}
	for index, packet := range packets {
		plaintext, pn, err := h3InitialPlaintext(packet, initialDCID)
		if err != nil {
			t.Fatalf("Initial packet %d: %v", index, err)
		}
		if index == 0 {
			firstPN = pn
		}
		r := bytes.NewReader(plaintext)
		read := func() uint64 {
			v, err := quicvarint.Read(r)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		for r.Len() > 0 {
			typ := read()
			switch typ {
			case 0, 1:
			case 2, 3:
				read()
				read()
				count := read()
				read()
				for i := uint64(0); i < count; i++ {
					read()
					read()
				}
				if typ == 3 {
					read()
					read()
					read()
				}
			case 6:
				offset, length := read(), read()
				if offset+length > uint64(len(data)) || length > uint64(r.Len()) {
					t.Fatal("invalid CRYPTO range")
				}
				if _, err := r.Read(data[offset : offset+length]); err != nil {
					t.Fatal(err)
				}
				for i := offset; i < offset+length; i++ {
					present[i] = true
				}
			default:
				t.Fatalf("unexpected Initial frame %d", typ)
			}
		}
	}
	if !present[0] || data[0] != 1 {
		t.Fatal("no ClientHello")
	}
	size := 4 + (int(data[1]) << 16) + (int(data[2]) << 8) + int(data[3])
	if size > len(data) {
		t.Fatal("oversized ClientHello")
	}
	for _, v := range present[:size] {
		if !v {
			t.Fatal("incomplete ClientHello capture")
		}
	}
	return data[:size], firstPN
}
func h3HelloExtensions(t *testing.T, hello []byte) map[uint16][]byte {
	t.Helper()
	b := hello[38:]
	if b[0] != 0 {
		t.Fatal("QUIC legacy session ID must be empty")
	}
	b = b[1:]
	b = b[2+int(binary.BigEndian.Uint16(b)):]
	b = b[1+int(b[0]):]
	length := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if length != len(b) {
		t.Fatal("extension length mismatch")
	}
	out := map[uint16][]byte{}
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatal("short extension")
		}
		id, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if n > len(b) {
			t.Fatal("short extension value")
		}
		if _, exists := out[id]; exists {
			t.Fatalf("duplicate extension %d", id)
		}
		out[id] = b[:n]
		b = b[n:]
	}
	return out
}
func h3QUICClientHello(t *testing.T) u.ClientHelloSpec {
	t.Helper()
	spec, err := u.UTLSIdToSpec(u.HelloChrome_155)
	if err != nil {
		t.Fatal(err)
	}
	// Test input only. This is a valid QUIC template, not a claimed browser capture.
	spec.TLSVersMin = u.VersionTLS13
	spec.TLSVersMax = u.VersionTLS13
	spec.CipherSuites = []uint16{u.TLS_AES_128_GCM_SHA256, u.TLS_AES_256_GCM_SHA384, u.TLS_CHACHA20_POLY1305_SHA256}
	var extensions []u.TLSExtension
	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case *u.RenegotiationInfoExtension, *u.SessionTicketExtension, *u.SupportedPointsExtension, *u.ExtendedMasterSecretExtension, *u.UtlsPaddingExtension, *u.ApplicationSettingsExtension, *u.ApplicationSettingsExtensionNew:
			continue
		case *u.SupportedVersionsExtension:
			e.Versions = []uint16{u.VersionTLS13}
		case *u.ALPNExtension:
			e.AlpnProtocols = []string{"h3"}
		}
		extensions = append(extensions, extension)
	}
	spec.Extensions = append(extensions, &u.QUICTransportParametersExtension{}, &u.UtlsPreSharedKeyExtension{})
	return spec
}
func TestHTTP3ExternalHandshakeOnWire(t *testing.T) {
	for _, disable := range []bool{false, true} {
		t.Run(fmt.Sprintf("disable-scrambling-%t", disable), func(t *testing.T) {
			peer := newH3Peer(t)
			layout := &transportparams.Layout{Order: []uint64{15, 100, 7, 6, 5, 4, 3, 1, 8, 9, 11, 14, 32, transportparams.Grease}, Additional: []transportparams.Parameter{{ID: 100, Value: []byte("external")}}}
			handshake := &quic.ClientHandshake{StreamReceiveWindows: &quic.StreamReceiveWindows{BidiLocal: 2 << 20, BidiRemote: 128 << 10, Uni: 64 << 10}, TransportParameters: layout, MaxDatagramFrameSize: 1200, InitialDestinationConnectionIDLength: 12, InitialPacketNumber: 17, DisableClientHelloScrambling: disable}
			template := h3QUICClientHello(t)
			builder := surf.NewClient().Builder().ForceHTTP3()
			client := builder.HTTP3Settings().ClientHandshake(handshake).ClientHelloSpec(&template).EnableDatagrams(true).Set().Timeout(5 * time.Second).Build().Unwrap()
			defer client.Close()
			// Both setter snapshots must survive subsequent mutations of the inputs.
			handshake.StreamReceiveWindows.BidiLocal = 99
			layout.Order[0] = 4
			layout.Additional[0].Value[0] = 'X'
			template.CipherSuites[0] = 0
			peer.request(t, client)
			hello, pn := h3CapturedHello(t, peer)
			if pn != 17 {
				t.Fatalf("initial PN=%d", pn)
			}
			extensions := h3HelloExtensions(t, hello)
			if !bytes.Equal(extensions[16], []byte{0, 3, 2, 'h', '3'}) {
				t.Fatalf("ALPN=%x", extensions[16])
			}
			if !bytes.Equal(extensions[43], []byte{2, 3, 4}) {
				t.Fatalf("supported_versions=%x", extensions[43])
			}
			var ids []uint64
			values := map[uint64][]byte{}
			r := bytes.NewReader(extensions[57])
			for r.Len() > 0 {
				id, err := quicvarint.Read(r)
				if err != nil {
					t.Fatal(err)
				}
				n, err := quicvarint.Read(r)
				if err != nil || n > uint64(r.Len()) {
					t.Fatal("bad parameter length")
				}
				v := make([]byte, n)
				r.Read(v)
				values[id] = v
				if id >= 27 && (id-27)%31 == 0 {
					id = transportparams.Grease
				}
				ids = append(ids, id)
			}
			want := []uint64{15, 100, 7, 6, 5, 4, 3, 1, 8, 9, 11, 14, 32, transportparams.Grease}
			if !slices.Equal(ids, want) {
				t.Fatalf("transport parameter order=%v, want %v", ids, want)
			}
			if string(values[100]) != "external" || len(values[15]) != 4 {
				t.Fatalf("transport parameters=%v", values)
			}
			for id, want := range map[uint64]uint64{5: 2 << 20, 6: 128 << 10, 7: 64 << 10, 32: 1200} {
				got, _, err := quicvarint.Parse(values[id])
				if err != nil || got != want {
					t.Fatalf("parameter %d=%d: %v", id, got, err)
				}
			}
			peer.packet.mu.Lock()
			initial := peer.packet.rawInitials[0]
			dcidLength := initial[5]
			peer.packet.mu.Unlock()
			if dcidLength != 12 {
				t.Fatalf("Initial DCID length=%d", dcidLength)
			}
			peer.mu.Lock()
			params := peer.parameters[0]
			peer.mu.Unlock()
			if params.InitialMaxStreamDataBidiLocal != 2<<20 || params.InitialMaxStreamDataBidiRemote != 128<<10 || params.InitialMaxStreamDataUni != 64<<10 || params.MaxDatagramFrameSize != 1200 {
				t.Fatalf("peer-decoded parameters=%+v", params)
			}

		})
	}
}

func TestHTTP3ExplicitClientHelloFailure(t *testing.T) {
	peer := newH3Peer(t)
	invalid := u.ClientHelloSpec{}
	client := surf.NewClient().Builder().ForceHTTP3().HTTP3Settings().ClientHelloSpec(&invalid).Set().Timeout(time.Second).Build().Unwrap()
	defer client.Close()
	if result := client.Get(g.String(peer.url)).Do(); result.IsOk() {
		t.Fatal("invalid template silently fell back to standard TLS")
	}
	factoryError := fmt.Errorf("external template failed")
	client2 := surf.NewClient().Builder().ForceHTTP3().HTTP3Settings().ClientHelloFactory(func() (u.ClientHelloSpec, error) { return u.ClientHelloSpec{}, factoryError }).Set().Timeout(time.Second).Build().Unwrap()
	defer client2.Close()
	if result := client2.Get(g.String(peer.url)).Do(); result.IsOk() {
		t.Fatal("factory error silently ignored")
	}
}

// A cache notification synchronizes on the ticket, not an arbitrary sleep.
type h3SessionCache struct {
	tls.ClientSessionCache
	stored chan struct{}
}

func (c *h3SessionCache) Put(key string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, state)
	if state != nil {
		select {
		case c.stored <- struct{}{}:
		default:
		}
	}
}
func TestHTTP3ClientHelloSessionResumption(t *testing.T) {
	peer := newH3Peer(t)
	cache := &h3SessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), stored: make(chan struct{}, 4)}
	template := h3QUICClientHello(t)
	client := surf.NewClient().Builder().ForceHTTP3().TLSConfig(&tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}).HTTP3Settings().ClientHelloSpec(&template).Set().Timeout(5 * time.Second).Build().Unwrap()
	defer client.Close()
	peer.request(t, client)
	select {
	case <-cache.stored:
	case <-time.After(5 * time.Second):
		t.Fatal("no session ticket stored in configured TLS cache")
	}
	client.GetClient().CloseIdleConnections()
	peer.request(t, client)
	peer.mu.Lock()
	resumed := slices.Clone(peer.resumed)
	peer.mu.Unlock()
	if !slices.Equal(resumed, []bool{false, true}) {
		t.Fatalf("server TLS resumption=%v", resumed)
	}
}
