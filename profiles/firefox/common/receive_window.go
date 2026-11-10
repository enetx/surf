package common

import "github.com/enetx/http/http2"

// ReceiveWindowUpdate follows kMinimumToAck and kEmergencyWindowThreshold.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2Session.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2Session.h
func ReceiveWindowUpdate(info http2.ReceiveWindowUpdateInfo) bool {
	return info.Pending >= 4<<20 || info.Available <= 96<<10
}
