package quic

import (
	"net"
	"reflect"
	"testing"
)

func TestInitialConnectionIDLengthDistribution(t *testing.T) {
	// Exhaustive histogram for Neqo's single random-byte construction; eight
	// occurs 144/256 times and twenty only once. No statistical/flaky test.
	want := map[int]int{8: 144, 9: 27, 10: 9, 11: 9, 12: 3, 13: 27, 14: 9, 15: 9, 16: 3, 17: 9, 18: 3, 19: 3, 20: 1}
	got := map[int]int{}
	for value := range 256 {
		got[initialDestinationConnectionIDLength(byte(value))]++
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("CID length histogram: %v", got)
	}
}

func TestInitialPacketSizeAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want uint16
	}{{"127.0.0.1", 1252}, {"::1", 1232}, {"::ffff:127.0.0.1", 1252}} {
		got, err := NewInitialPacketSize(&net.UDPAddr{IP: net.ParseIP(tc.ip), Port: 443})
		if err != nil || got != tc.want {
			t.Fatalf("%s: size=%d err=%v", tc.ip, got, err)
		}
	}
	if _, err := NewInitialPacketSize(nil); err == nil {
		t.Fatal("unresolved address accepted")
	}
}
