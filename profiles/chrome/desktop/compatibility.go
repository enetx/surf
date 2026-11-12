package desktop

import (
	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
)

// Headers applies the desktop declaration while preserving explicit values.
var Headers = common.Headers

// BuildHeaders constructs the desktop identity and optional header positions.
func BuildHeaders(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	return common.BuildHeaders(os)
}

// BuildRequestHeaders returns fresh desktop defaults in request-specific order.
func BuildRequestHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.BuildRequestHeaders(c)
}

// NavigationHeaders returns the desktop document-request header declaration.
func NavigationHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.NavigationHeaders(c)
}

// FetchHeaders returns the desktop renderer-request header declaration.
func FetchHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.FetchHeaders(c)
}
