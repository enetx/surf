package profiles

import (
	"context"
	"strings"

	"github.com/enetx/http"
)

// RequestKind selects a browser header scenario independently of the HTTP method
// and the availability of Fetch Metadata on the target origin.
type RequestKind uint8

const (
	// AutomaticRequest uses explicit Fetch Metadata, then the method's default.
	AutomaticRequest RequestKind = iota
	// NavigationRequest selects document-navigation defaults.
	NavigationRequest
	// FetchRequest selects ordinary fetch defaults.
	FetchRequest
)

type requestKindKey struct{}

// WithRequestKind records a browser request scenario for header and transport
// policies. It does not change the HTTP method or emit Fetch Metadata.
func WithRequestKind(ctx context.Context, kind RequestKind) context.Context {
	return context.WithValue(ctx, requestKindKey{}, kind)
}

// RequestKindFromContext returns a scenario recorded by WithRequestKind. The
// boolean distinguishes an explicit AutomaticRequest from an absent selection.
// A nil context has no selection.
func RequestKindFromContext(ctx context.Context) (RequestKind, bool) {
	if ctx == nil {
		return AutomaticRequest, false
	}
	kind, ok := ctx.Value(requestKindKey{}).(RequestKind)
	return kind, ok
}

// HeaderContext describes one preparation of browser request headers.
// Factories must not mutate Request, read its body, or change shared profile data.
type HeaderContext struct {
	// Request supplies the method, current fields and framing information. Nil
	// with AutomaticRequest selects the default GET navigation template.
	Request *http.Request
	// OS selects the target identity, independently of the Go host OS.
	OS OSKey
	// Kind selects navigation or fetch without requiring an emitted metadata
	// header. An explicit nonempty Sec-Fetch-Mode still takes precedence.
	Kind RequestKind
	// Protocol is zero for logical defaults, then the actual HTTP major version
	// (1, 2 or 3) selected for one transport attempt, including fallback.
	Protocol int
	// CriticalCH identifies a navigation restarted to supply critical hints.
	CriticalCH bool
	// Redirect identifies an attempt following a redirect, including Std adapters.
	// It preserves the operation's scenario when a POST becomes a GET.
	Redirect bool
}

// Navigation reports the request's header scenario. An explicit nonempty
// Sec-Fetch-Mode takes precedence, followed by Kind and the request context.
// AutomaticRequest defaults
// GET/HEAD to navigation and other methods to fetch. A POST can select navigation
// and a GET can select fetch without emitting Fetch Metadata.
func (c HeaderContext) Navigation() bool {
	if c.Request != nil {
		for name, values := range c.Request.Header {
			if strings.EqualFold(name, "sec-fetch-mode") && len(values) > 0 && values[0] != "" {
				return strings.EqualFold(values[0], "navigate")
			}
		}
	}

	kind := c.Kind
	if kind == AutomaticRequest && c.Request != nil {
		kind, _ = RequestKindFromContext(c.Request.Context())
	}
	if kind == NavigationRequest {
		return true
	}

	if kind == FetchRequest {
		return false
	}

	if c.Request == nil {
		return true
	}

	return c.Request.Method == "" || c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead
}

// HasBody reports an upload, including an explicitly supplied empty body with a
// replay factory. It never reads the body. An absent body remains distinct from
// a zero-byte upload when selecting browser framing positions.
func (c HeaderContext) HasBody() bool {
	return c.Request != nil &&
		(c.Request.ContentLength > 0 || c.Request.GetBody != nil || c.Request.Body != nil && c.Request.Body != http.NoBody)
}
