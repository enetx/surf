package surf

import (
	"github.com/enetx/http"
	h3transport "github.com/enetx/surf/internal/http3"
)

type requestHeadersPolicy func(*http.Request, int)

func withProtocolHeaders(req *http.Request, policy requestHeadersPolicy, major int) *http.Request {
	return h3transport.WithProtocolHeaders(req, policy, major)
}
