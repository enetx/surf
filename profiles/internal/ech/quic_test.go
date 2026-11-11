package ech

import (
	"bytes"
	"testing"

	"github.com/enetx/quic-go/quicvarint"
)

func TestPublicQUICParameters(t *testing.T) {
	var full, want []byte
	for _, id := range []uint64{1, 4, 5, 6, 7, 8, 9, 11, 14, 15, 17, 29, 32, 0, 2, 3, 10, 16, 0xff02de1a} {
		parameter := quicvarint.AppendWithLen(nil, id, 8)
		parameter = quicvarint.AppendWithLen(parameter, 2, 2)
		parameter = append(parameter, 1, 2)
		full = append(full, parameter...)
		switch id {
		case 0, 2, 3, 10, 11, 15, 16, 17:
			want = append(want, parameter...)
		}
	}
	before := bytes.Clone(full)
	got, err := PublicQUICParameters(full)
	if err != nil || !bytes.Equal(got, want) || !bytes.Equal(full, before) {
		t.Fatalf("public parameter filtering: %x %v", got, err)
	}
	got[0] ^= 1
	if !bytes.Equal(full, before) {
		t.Fatal("output aliases engine parameters")
	}
	for _, malformed := range [][]byte{{0x40}, {1}, {1, 0x40}, {1, 4, 0}} {
		if _, err := PublicQUICParameters(malformed); err == nil {
			t.Fatalf("accepted malformed %x", malformed)
		}
	}
	if empty, err := PublicQUICParameters(nil); err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("empty public offer must remain distinguishable from no override")
	}
}

func FuzzPublicQUICParameters(f *testing.F) {
	f.Add([]byte{11, 1, 20, 15, 0})
	f.Add([]byte{1, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = PublicQUICParameters(data) })
}
