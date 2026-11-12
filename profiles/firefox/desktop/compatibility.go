package desktop

import (
	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox/common"
)

// Headers applies the desktop request preset to an ordered map.
var Headers = common.Headers

// BuildHeaders constructs the static desktop identity fragment.
func BuildHeaders(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	return common.BuildDesktopHeaders(os)
}

// BuildRequestHeaders returns fresh desktop defaults for the request context.
func BuildRequestHeaders(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.BuildRequestHeaders(ctx)
}

// NavigationHeaders returns the desktop document-request header declaration.
func NavigationHeaders(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.NavigationHeaders(ctx)
}

// FetchHeaders returns the desktop fetch-request header declaration.
func FetchHeaders(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.FetchHeaders(ctx)
}

// ProtocolHeaders applies the desktop protocol defaults declared in common.
// Explicit header values and pseudo-header metadata retain their ownership.
func ProtocolHeaders(headers http.Header, major int) {
	common.ProtocolHeaders(headers, major)
}
