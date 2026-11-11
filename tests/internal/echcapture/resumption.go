package echcapture

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"slices"
)

type Provenance struct {
	NetLogSHA256   string `json:"netlog_sha256,omitempty"`
	PCAPSHA256     string `json:"pcap_sha256,omitempty"`
	AnalysisSHA256 string `json:"analysis_pcap_sha256,omitempty"`
	Method         string `json:"method"`
}

type WireEvidence struct {
	EarlyPackets        int `json:"earlyPackets"`
	EarlyControlPackets int `json:"earlyControlPackets"`
	EarlyRequestPackets int `json:"earlyRequestPackets"`
	Source              int `json:"source,omitempty"`
}

// RawCapture is private input. Inner contains actual ticket identities/binders;
// only NewReference's redacted result belongs in a public fixture directory.
type RawCapture struct {
	Implementation      string       `json:"implementation,omitempty"`
	Browser             string       `json:"browser"`
	Platform            string       `json:"platform"`
	Transport           string       `json:"transport"`
	Outer               []byte       `json:"outer"`
	Inner               []byte       `json:"inner"`
	ServerHello         []byte       `json:"serverHello"`
	EncryptedExtensions []byte       `json:"encryptedExtensions"`
	Wire                WireEvidence `json:"wire"`
	Provenance          Provenance   `json:"provenance"`
}

type PSKShape struct {
	Identities []int  `json:"identity_lengths"`
	Binders    []int  `json:"binder_lengths"`
	Selected   int    `json:"selected_identity"`
	Outer      string `json:"outer_policy"`
}

type EarlyData struct {
	Offered        bool `json:"offered"`
	Accepted       bool `json:"accepted"`
	RequestPackets int  `json:"request_packets"`
	Packets        int  `json:"packets"`
	ControlPackets int  `json:"control_packets"`
}

type Reference struct {
	Implementation     string     `json:"implementation"`
	Schema             int        `json:"schema"`
	Browser            string     `json:"browser"`
	Platform           string     `json:"platform"`
	Transport          string     `json:"transport"`
	Provenance         Provenance `json:"provenance"`
	Outer              []byte     `json:"outer"`
	Inner              []byte     `json:"inner"`
	ServerHello        []byte     `json:"server_hello"`
	ConfirmationHash   []byte     `json:"original_confirmation_transcript_hash"`
	PSK                PSKShape   `json:"psk"`
	EarlyData          EarlyData  `json:"early_data"`
	ServerExtensions   []uint16   `json:"server_encrypted_extension_ids"`
	RedactedExtensions []uint16   `json:"redacted_extensions"`
}

func confirmationHash(cipher uint16) (func() hash.Hash, error) {
	switch cipher {
	case 0x1301, 0x1303:
		return sha256.New, nil
	case 0x1302:
		return sha512.New384, nil
	default:
		return nil, errors.New("unsupported TLS 1.3 confirmation cipher")
	}
}

// VerifyECHConfirmation checks RFC 9849 section 6.1.4 independently of the TLS
// engine. The original transcript digest lets sanitized fixtures retain this
// proof without publishing the private PSK input to that digest.
// https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4
func VerifyECHConfirmation(innerRandom, serverHello, transcriptHash []byte) error {
	server, err := ReadServerHello(serverHello)
	if err != nil {
		return err
	}
	h, err := confirmationHash(server.Cipher)
	if err != nil {
		return err
	}
	if len(innerRandom) != 32 || len(transcriptHash) != h().Size() {
		return errors.New("invalid ECH confirmation input lengths")
	}
	prk := hmac.New(h, make([]byte, h().Size()))
	prk.Write(innerRandom)
	label := []byte("tls13 ech accept confirmation")
	info := []byte{0, 8, byte(len(label))}
	info = append(info, label...)
	info = append(info, byte(len(transcriptHash)))
	info = append(info, transcriptHash...)
	info = append(info, 1) // One HKDF-Expand block; only eight output bytes.
	mac := hmac.New(h, prk.Sum(nil))
	mac.Write(info)
	if !hmac.Equal(mac.Sum(nil)[:8], server.Random[24:]) {
		return errors.New("server did not authenticate the captured ECH inner")
	}
	return nil
}

func NewReference(capture RawCapture) (*Reference, error) {
	inner, err := ReadClientHello(capture.Inner)
	if err != nil {
		return nil, err
	}
	outer, err := ReadClientHello(capture.Outer)
	if err != nil {
		return nil, err
	}
	server, err := ReadServerHello(capture.ServerHello)
	if err != nil {
		return nil, err
	}
	if capture.Transport != "tcp" && capture.Transport != "quic" {
		return nil, errors.New("unknown capture transport")
	}
	if inner.Version != 0x0303 || !bytes.Equal(inner.Compression, []byte{0}) ||
		!bytes.Equal(inner.SessionID, outer.SessionID) || !bytes.Equal(inner.SessionID, server.SessionID) ||
		!slices.Contains(inner.CipherSuites, server.Cipher) {
		return nil, errors.New("captured client and server hellos do not form a TLS 1.3 pair")
	}
	if version, _ := server.Extension(43); !bytes.Equal(version, []byte{3, 4}) {
		return nil, errors.New("server did not select TLS 1.3")
	}
	if marker, _ := inner.Extension(65037); !bytes.Equal(marker, []byte{1}) {
		return nil, errors.New("captured private hello lacks the ECH inner marker")
	}
	if marker, _ := outer.Extension(65037); len(marker) == 0 || marker[0] != 0 {
		return nil, errors.New("captured outer hello lacks real ECH")
	}
	if data, _ := outer.Extension(65037); data != nil {
		if _, err := extensionFeature(Extension{65037, data}, ""); err != nil {
			return nil, err
		}
	}
	for _, ext := range server.Extensions {
		if ext.ID != 41 && ext.ID != 43 && ext.ID != 51 {
			return nil, fmt.Errorf("unexpected resumed ServerHello extension %d", ext.ID)
		}
	}
	h, err := confirmationHash(server.Cipher)
	if err != nil {
		return nil, err
	}
	transcript := h()
	transcript.Write(capture.Inner)
	transcript.Write(capture.ServerHello[:30])
	transcript.Write(make([]byte, 8))
	transcript.Write(capture.ServerHello[38:])
	digest := transcript.Sum(nil)
	if err := VerifyECHConfirmation(inner.Random, capture.ServerHello, digest); err != nil {
		return nil, err
	}
	pskData, _ := inner.Extension(41)
	psk, err := ReadPSK(pskData)
	if err != nil {
		return nil, err
	}
	selected, err := SelectedPSK(server)
	if err != nil || selected >= len(psk.Identities) {
		return nil, errors.New("server selected no valid captured PSK identity")
	}
	if len(psk.Binders[selected]) != h().Size() {
		return nil, errors.New("selected PSK binder length does not match its cipher hash")
	}
	policy := "omitted"
	if data, present := outer.Extension(41); present {
		public, err := ReadPSK(data)
		if err != nil {
			return nil, err
		}
		a, b := PSKLengths(psk)
		c, d := PSKLengths(public)
		if !slices.Equal(a, c) || !slices.Equal(b, d) {
			return nil, errors.New("public and private PSK framing differ")
		}
		policy = "randomized"
	}
	for _, identity := range psk.Identities {
		if bytes.Contains(capture.Outer, identity) {
			return nil, errors.New("private PSK identity is visible in the captured outer")
		}
	}
	serverExts, err := ReadEncryptedExtensions(capture.EncryptedExtensions)
	if err != nil {
		return nil, err
	}
	_, offered := inner.Extension(42)
	if capture.Implementation == "" {
		capture.Implementation = "native"
	}
	if capture.Implementation != "native" && capture.Implementation != "surf" {
		return nil, errors.New("unknown capture implementation")
	}
	ref := &Reference{Schema: 1, Browser: capture.Browser, Platform: capture.Platform,
		Implementation: capture.Implementation,
		Transport:      capture.Transport, Provenance: capture.Provenance, ServerHello: bytes.Clone(capture.ServerHello),
		ConfirmationHash: digest, EarlyData: EarlyData{Offered: offered, Packets: capture.Wire.EarlyPackets,
			ControlPackets: capture.Wire.EarlyControlPackets, RequestPackets: capture.Wire.EarlyRequestPackets},
		PSK: PSKShape{Selected: selected, Outer: policy}, RedactedExtensions: []uint16{35, 41}}
	ref.PSK.Identities, ref.PSK.Binders = PSKLengths(psk)
	for _, ext := range serverExts {
		ref.ServerExtensions = append(ref.ServerExtensions, ext.ID)
		if ext.ID == 42 {
			if len(ext.Data) != 0 || !offered || selected != 0 {
				return nil, errors.New("invalid server early-data acceptance")
			}
			ref.EarlyData.Accepted = true
		}
	}
	if data, present := inner.Extension(42); present && len(data) != 0 {
		return nil, errors.New("nonempty early-data offer")
	}
	wire := capture.Wire
	if wire.EarlyPackets < 0 || wire.EarlyControlPackets < 0 || wire.EarlyRequestPackets < 0 ||
		wire.EarlyControlPackets > wire.EarlyPackets || wire.EarlyRequestPackets > wire.EarlyPackets ||
		wire.EarlyPackets > 0 && !offered || ref.EarlyData.Accepted && wire.EarlyPackets == 0 {
		return nil, errors.New("early-data state has no matching packet evidence")
	}
	ref.Outer, err = RedactClientHello(capture.Outer)
	if err != nil {
		return nil, err
	}
	ref.Inner, err = RedactClientHello(capture.Inner)
	return ref, err
}

func IsGREASE(id uint16) bool { return id&0x0f0f == 0x0a0a }

func Uint16Vector(data []byte) ([]uint16, error) {
	if len(data)%2 != 0 {
		return nil, errors.New("odd uint16 vector")
	}
	result := make([]uint16, len(data)/2)
	for i := range result {
		result[i] = binary.BigEndian.Uint16(data[i*2:])
	}
	return result, nil
}
