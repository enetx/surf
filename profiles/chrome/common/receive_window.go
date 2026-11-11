package common

import (
	"time"

	"github.com/enetx/http/http2"
)

// ReceiveWindowUpdate follows SpdySession/SpdyStream credit batching. The time
// threshold is checked on returned credit, without an independently armed timer.
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/spdy/spdy_session.cc
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/spdy/spdy_stream.cc
// https://github.com/chromium/chromium/blob/157.0.8103.51/net/spdy/spdy_session.h
func ReceiveWindowUpdate(info http2.ReceiveWindowUpdateInfo) bool {
	return info.Pending > info.Window/2 || info.Elapsed >= 5*time.Second
}
