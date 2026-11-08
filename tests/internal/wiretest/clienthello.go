// Package wiretest normalizes serialized browser handshakes for golden tests.
package wiretest

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// HelloDetails exposes connection-dependent fields for additional wire assertions.
type HelloDetails struct {
	SignatureGREASE  uint16
	KeyShares        map[uint16][]byte
	ECHPayloadLength int
	ECHAEAD          uint16
}

func greaseID(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }

func wireID(v uint16) string {
	if greaseID(v) {
		return "GREASE"
	}
	return strconv.Itoa(int(v))
}

func wireIDs(b []byte, sep string) string {
	var values []string
	for len(b) >= 2 {
		values = append(values, wireID(binary.BigEndian.Uint16(b)))
		b = b[2:]
	}
	return strings.Join(values, sep)
}

// ClientHello normalizes a serialized handshake while preserving
// ordered ciphers, groups, signature schemes and trust anchor bytes.
func ClientHello(t *testing.T, raw []byte, shuffle bool) (string, HelloDetails) {
	t.Helper()

	pos := 38 // Handshake header, legacy version and random.
	take := func(n int) []byte {
		t.Helper()
		if n < 0 || pos+n > len(raw) {
			t.Fatal("truncated ClientHello")
		}
		b := raw[pos : pos+n]
		pos += n
		return b
	}
	session := take(int(take(1)[0]))
	ciphers := take(int(binary.BigEndian.Uint16(take(2))))
	compression := take(int(take(1)[0]))
	extensions := take(int(binary.BigEndian.Uint16(take(2))))
	var ids, lines []string
	var signatureGREASE uint16
	details := HelloDetails{KeyShares: make(map[uint16][]byte)}
	for len(extensions) >= 4 {
		id := binary.BigEndian.Uint16(extensions[:2])
		n := int(binary.BigEndian.Uint16(extensions[2:4]))
		if n+4 > len(extensions) {
			t.Fatal("truncated extension")
		}
		b := extensions[4 : 4+n]
		extensions = extensions[4+n:]
		ids = append(ids, wireID(id))
		value := hex.EncodeToString(b)
		switch id {
		case 10, 13:
			value = wireIDs(b[2:], " ")
			if id == 13 {
				signatureGREASE = binary.BigEndian.Uint16(b[2:4])
			}
		case 27, 43:
			value = wireIDs(b[1:], " ")
		case 51:
			var shares []string
			for b = b[2:]; len(b) >= 4; {
				group := binary.BigEndian.Uint16(b[:2])
				size := int(binary.BigEndian.Uint16(b[2:4]))
				shares = append(shares, fmt.Sprintf("%s:%d", wireID(group), size))
				details.KeyShares[group] = b[4 : 4+size]
				b = b[4+size:]
			}
			value = strings.Join(shares, " ")
		case 65037:
			encLen := int(binary.BigEndian.Uint16(b[6:8]))
			payloadLen := binary.BigEndian.Uint16(b[8+encLen : 10+encLen])
			details.ECHPayloadLength = int(payloadLen)
			details.ECHAEAD = binary.BigEndian.Uint16(b[3:5])
			value = fmt.Sprintf("type=%d kdf=%d enc=%d payload%%16=%d", b[0], binary.BigEndian.Uint16(b[1:3]), encLen, payloadLen%16)
		}
		line := strings.TrimSpace("ext " + wireID(id) + ": " + value)
		// The two GREASE bodies have a stable order in the reference snapshot.
		lines = append(lines, line)
	}
	if shuffle && !greaseID(signatureGREASE) {
		t.Errorf("signature_algorithms starts with %#04x, want GREASE", signatureGREASE)
	}
	kind := "extensions"
	if shuffle {
		slices.Sort(ids)
		kind += " (permuted)"
	}
	slices.SortFunc(lines, func(a, b string) int {
		aID, _, _ := strings.Cut(a, ":")
		bID, _, _ := strings.Cut(b, ":")
		if aID == bID {
			return strings.Compare(a, b)
		}
		return strings.Compare(aID, bID)
	})
	details.SignatureGREASE = signatureGREASE
	return fmt.Sprintf("%s %s\nlegacy_version 0x%04x\nsession_id %d bytes\ncipher_suites %s\ncompression %s\n%s\n",
		kind, strings.Join(ids, ","), binary.BigEndian.Uint16(raw[4:6]), len(session), wireIDs(ciphers, ","), hex.EncodeToString(compression), strings.Join(lines, "\n")), details
}
