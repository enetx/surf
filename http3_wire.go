package surf

import (
	"slices"

	"github.com/enetx/http"
	"github.com/enetx/quic-go/http3"
)

// HTTP3GreaseFrame describes one RFC 9114 reserved frame and its payload.
type HTTP3GreaseFrame = http3.GreaseFrame

func (h *HTTP3Settings) wire() *http3.WireConfig {
	if h.wireConfig == nil {
		h.wireConfig = &http3.WireConfig{}
	}

	return h.wireConfig
}

func cloneHTTP3GreaseFrames(frames []HTTP3GreaseFrame) []HTTP3GreaseFrame {
	copy := slices.Clone(frames)
	for i := range copy {
		copy[i].Payload = slices.Clone(copy[i].Payload)
	}

	return copy
}

// ControlGreaseFrames adds reserved frames after SETTINGS on every connection.
// Types must be 0x1f*N+0x21. Frames and payloads are copied.
func (h *HTTP3Settings) ControlGreaseFrames(frames ...HTTP3GreaseFrame) *HTTP3Settings {
	copy := cloneHTTP3GreaseFrames(frames)
	return h.ControlGreaseFramesFactory(func() ([]HTTP3GreaseFrame, error) { return copy, nil })
}

// ControlGreaseFramesFactory generates fresh frames once per connection.
// The callback must be safe for concurrent connections.
func (h *HTTP3Settings) ControlGreaseFramesFactory(factory func() ([]HTTP3GreaseFrame, error)) *HTTP3Settings {
	h.wire().ControlGreaseFrames = factory
	return h
}

// RequestGreaseFrames adds reserved frames before each request's HEADERS.
// Types must be 0x1f*N+0x21. Frames and payloads are copied.
func (h *HTTP3Settings) RequestGreaseFrames(frames ...HTTP3GreaseFrame) *HTTP3Settings {
	copy := cloneHTTP3GreaseFrames(frames)
	return h.RequestGreaseFramesFactory(func(*http.Request) ([]HTTP3GreaseFrame, error) { return copy, nil })
}

// RequestGreaseFramesFactory generates frames for each request. The callback
// must be safe for concurrent connections and must not mutate the request.
func (h *HTTP3Settings) RequestGreaseFramesFactory(
	factory func(*http.Request) ([]HTTP3GreaseFrame, error),
) *HTTP3Settings {
	h.wire().RequestGreaseFrames = factory
	return h
}

// PriorityUpdates sends RFC 9218 control frames for explicit, nondefault
// request Priority headers. Independent of GREASE and local StreamPriority.
func (h *HTTP3Settings) PriorityUpdates(enabled bool) *HTTP3Settings {
	h.wire().SendPriorityUpdates = enabled
	return h
}

// CoalesceInitialSettings queues SETTINGS with the first post-handshake flight
// when peer flow-control credit permits. Backpressure uses an asynchronous
// write on the same control stream. Control frame factories must not block.
func (h *HTTP3Settings) CoalesceInitialSettings(enabled bool) *HTTP3Settings {
	h.wire().CoalesceInitialSettings = enabled
	return h
}
