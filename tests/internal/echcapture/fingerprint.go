package echcapture

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

type Feature struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type Fingerprint struct {
	Version         uint16    `json:"legacy_version"`
	SessionIDLength int       `json:"session_id_length"`
	Ciphers         []string  `json:"ciphers"`
	Compression     string    `json:"compression"`
	Extensions      []Feature `json:"extensions"`
}

func grease16(id uint16) string {
	if IsGREASE(id) {
		return "GREASE"
	}
	return strconv.Itoa(int(id))
}

// StableFingerprint removes explicitly variable material, retaining opaque
// extension payloads and fixed parameter encodings. Chromium permutes TLS/TP
// order; Neqo permutes TLS extensions but retains its TP order. Firefox TCP
// remains ordered. Paired-hello tests separately verify the ECH layout rules.
func StableFingerprint(raw []byte, browser, transport string) (*Fingerprint, error) {
	hello, err := ReadClientHello(raw)
	if err != nil {
		return nil, err
	}
	if browser != "chrome" && browser != "firefox" || transport != "tcp" && transport != "quic" {
		return nil, errors.New("unknown fingerprint profile")
	}
	fp := &Fingerprint{Version: hello.Version, SessionIDLength: len(hello.SessionID),
		Compression: hex.EncodeToString(hello.Compression)}
	for _, cipher := range hello.CipherSuites {
		fp.Ciphers = append(fp.Ciphers, grease16(cipher))
	}
	for _, ext := range hello.Extensions {
		value, err := extensionFeature(ext, browser)
		if err != nil {
			return nil, fmt.Errorf("extension %d: %w", ext.ID, err)
		}
		fp.Extensions = append(fp.Extensions, Feature{grease16(ext.ID), value})
	}
	if browser == "chrome" || transport == "quic" {
		slices.SortFunc(fp.Extensions, func(a, b Feature) int {
			if n := strings.Compare(a.ID, b.ID); n != 0 {
				return n
			}
			return strings.Compare(a.Value, b.Value)
		})
	}
	return fp, nil
}

func extensionFeature(ext Extension, browser string) (string, error) {
	s := cryptobyte.String(ext.Data)
	var vector cryptobyte.String
	switch ext.ID {
	case 10, 13, 43:
		valid := s.ReadUint16LengthPrefixed(&vector)
		if ext.ID == 43 {
			s = cryptobyte.String(ext.Data)
			valid = s.ReadUint8LengthPrefixed(&vector)
		}
		if !valid || !s.Empty() {
			return "", errors.New("invalid algorithm/version vector")
		}
		ids, err := Uint16Vector(vector)
		if err != nil {
			return "", err
		}
		values := make([]string, len(ids))
		for i, id := range ids {
			values[i] = grease16(id)
		}
		return strings.Join(values, ","), nil
	case 35:
		return fmt.Sprintf("ticket:%d", len(ext.Data)), nil
	case 41:
		psk, err := ReadPSK(ext.Data)
		if err != nil {
			return "", err
		}
		ids, binders := PSKLengths(psk)
		return fmt.Sprintf("identities:%v;binders:%v", ids, binders), nil
	case 44:
		if !s.ReadUint16LengthPrefixed(&vector) || !s.Empty() {
			return "", errors.New("invalid HRR cookie")
		}
		return fmt.Sprintf("cookie:%d", len(vector)), nil
	case 51:
		if !s.ReadUint16LengthPrefixed(&vector) || !s.Empty() {
			return "", errors.New("invalid key-share vector")
		}
		var shares []string
		for !vector.Empty() {
			var group uint16
			var key cryptobyte.String
			if !vector.ReadUint16(&group) || !vector.ReadUint16LengthPrefixed(&key) || key.Empty() {
				return "", errors.New("invalid key share")
			}
			shares = append(shares, fmt.Sprintf("%s/%d", grease16(group), len(key)))
		}
		return strings.Join(shares, ","), nil
	case 57:
		return transportFeature(ext.Data, browser)
	case 65037:
		if len(ext.Data) == 1 && ext.Data[0] == 1 {
			return "inner", nil
		}
		var typ, config uint8
		var kdf, aead uint16
		var enc, payload cryptobyte.String
		if !s.ReadUint8(&typ) || typ != 0 || !s.ReadUint16(&kdf) || !s.ReadUint16(&aead) ||
			!s.ReadUint8(&config) || !s.ReadUint16LengthPrefixed(&enc) ||
			!s.ReadUint16LengthPrefixed(&payload) || !s.Empty() {
			return "", errors.New("invalid ECH outer")
		}
		return fmt.Sprintf("outer:kdf=%d;aead=%d;enc=%d;payload=%d", kdf, aead, len(enc), len(payload)), nil
	default:
		return hex.EncodeToString(ext.Data), nil
	}
}

func readVarint(raw *[]byte) (uint64, int, error) {
	if len(*raw) == 0 {
		return 0, 0, errors.New("missing QUIC varint")
	}
	n := 1 << ((*raw)[0] >> 6)
	if len(*raw) < n {
		return 0, 0, errors.New("truncated QUIC varint")
	}
	v := uint64((*raw)[0] & 63)
	for _, b := range (*raw)[1:n] {
		v = v<<8 | uint64(b)
	}
	*raw = (*raw)[n:]
	return v, n, nil
}

func transportFeature(raw []byte, browser string) (string, error) {
	var features []string
	seen := make(map[uint64]bool)
	for len(raw) > 0 {
		id, iw, err := readVarint(&raw)
		if err != nil {
			return "", err
		}
		length, lw, err := readVarint(&raw)
		if err != nil || length > uint64(len(raw)) || seen[id] {
			return "", errors.New("invalid or duplicate QUIC parameter")
		}
		seen[id] = true
		data := raw[:int(length)]
		raw = raw[int(length):]
		if id%31 == 27 && id != 0xff02de1a {
			features = append(features, "GREASE")
			continue
		}
		value := hex.EncodeToString(data)
		switch id {
		case 0x3127:
			// QUICHE's initial_round_trip_time_us depends on network history.
			// Retain presence and minimal-encoding policy. The integer width
			// itself changes with measured RTT (e.g. 14ms vs 50ms).
			// https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/crypto/transport_parameters.cc#L90
			integer := data
			estimate, width, err := readVarint(&integer)
			if err != nil || len(integer) != 0 {
				return "", errors.New("invalid initial RTT parameter")
			}
			minimum := 1
			for _, boundary := range []uint64{1 << 6, 1 << 14, 1 << 30} {
				if estimate >= boundary {
					minimum *= 2
				}
			}
			value = "rtt-us:minimal"
			if width != minimum {
				value = fmt.Sprintf("rtt-us:nonminimal-%d-bytes", width)
			}
			if estimate == 0 {
				value += ":zero"
			}
		case 15:
			value = fmt.Sprintf("cid:%d", len(data))
		case 17:
			if len(data) < 8 || len(data)%4 != 0 {
				return "", errors.New("invalid QUIC version information")
			}
			var versions []string
			for i := 4; i < len(data); i += 4 {
				v := binary.BigEndian.Uint32(data[i : i+4])
				if v&0x0f0f0f0f == 0x0a0a0a0a {
					versions = append(versions, "GREASE")
				} else {
					versions = append(versions, fmt.Sprintf("%08x", v))
				}
			}
			if browser == "chrome" {
				slices.Sort(versions)
			}
			value = fmt.Sprintf("%08x@%s", binary.BigEndian.Uint32(data[:4]), strings.Join(versions, ","))
		}
		features = append(features, fmt.Sprintf("%d/%d/%d:%s", id, iw, lw, value))
	}
	if browser == "chrome" {
		slices.Sort(features)
	}
	return strings.Join(features, ";"), nil
}
