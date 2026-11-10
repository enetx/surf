package surf

import (
	"github.com/enetx/http"
	"github.com/enetx/surf/profiles"
)

// withProtocolHeaders applies profile defaults to a private attempt. Keeping
// them out of the original request lets fallback select different defaults
// without confusing them with headers supplied by the caller.
func withProtocolHeaders(req *http.Request, policy profiles.ProtocolHeaders, major int) *http.Request {
	if policy == nil {
		return req
	}

	clone := *req
	clone.Header = req.Header.Clone()
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	policy(clone.Header, major)
	return &clone
}
