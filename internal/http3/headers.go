package h3transport

import (
	"slices"

	"github.com/enetx/http"
	"github.com/enetx/quic-go/http3"
)

// WithProtocolHeaders applies profile defaults to a private attempt. Keeping
// them out of the original request lets fallback select different defaults
// without confusing them with headers supplied by the caller.
func WithProtocolHeaders(req *http.Request, policy func(*http.Request, int), major int) *http.Request {
	if policy == nil {
		return req
	}

	clone := *req
	clone.Header = req.Header.Clone()
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}

	policy(&clone, major)

	return &clone
}

func CloneGreaseFrames(frames []http3.GreaseFrame) []http3.GreaseFrame {
	copy := slices.Clone(frames)
	for i := range copy {
		copy[i].Payload = slices.Clone(copy[i].Payload)
	}

	return copy
}
