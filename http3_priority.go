package surf

import "github.com/enetx/quic-go/http3"

// HTTP3PriorityUpdater queues RFC 9218 priority changes for one open request.
// Update is concurrency safe; it does not change local QUIC upload scheduling.
type HTTP3PriorityUpdater = http3.PriorityUpdater

// HTTP3PriorityUpdates calls handler after HTTP/3 request HEADERS are sent on
// each attempt. Return promptly; retain the updater to change priority while
// the response is open. HTTP/1 and HTTP/2 do not invoke the handler.
func (req *Request) HTTP3PriorityUpdates(handler func(*HTTP3PriorityUpdater)) *Request {
	req.http3PriorityHandler = handler
	req.http3PrioritySet = true

	return req
}

// CompactPriorityUpdates omits spaces after commas in PRIORITY_UPDATE fields.
// It applies to initial frames and later HTTP3PriorityUpdater.Update calls.
func (h *HTTP3Settings) CompactPriorityUpdates(enabled bool) *HTTP3Settings {
	h.wire().CompactPriorityUpdates = enabled
	return h
}

func (req *Request) prepareHTTP3Priority() {
	if req.http3PrioritySet {
		req.request = req.request.WithContext(
			http3.WithPriorityUpdateHandler(req.request.Context(), req.http3PriorityHandler),
		)
	}
}
