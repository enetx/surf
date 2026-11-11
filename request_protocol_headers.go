package surf

import "github.com/enetx/http"

type requestHeadersPolicy func(*http.Request, int)

// withProtocolHeaders applies profile defaults to a private attempt. Keeping
// them out of the original request lets fallback select different defaults
// without confusing them with headers supplied by the caller.
func withProtocolHeaders(req *http.Request, policy requestHeadersPolicy, major int) *http.Request {
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
