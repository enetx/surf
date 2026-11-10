package surf

import "github.com/enetx/http/http2"

type HTTP2ReceiveWindowUpdateInfo = http2.ReceiveWindowUpdateInfo

// StreamReceiveWindow raises each client-created stream's credit after HEADERS.
// Zero uses InitialWindowSize; a nonzero window must be at least that size.
func (h *HTTP2Settings) StreamReceiveWindow(size uint32) *HTTP2Settings {
	h.streamReceiveWindow = size
	return h
}

// ReceiveWindowUpdatePolicy controls batching of returned HTTP/2 receive credit.
// Nil restores native behavior. The callback runs under the connection lock;
// it must return promptly, be concurrency safe and never reenter the transport.
// Credit is always refreshed when the peer's available window is exhausted.
func (h *HTTP2Settings) ReceiveWindowUpdatePolicy(policy func(HTTP2ReceiveWindowUpdateInfo) bool) *HTTP2Settings {
	h.receiveWindowUpdatePolicy = policy
	return h
}
