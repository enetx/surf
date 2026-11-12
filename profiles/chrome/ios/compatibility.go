package ios

import (
	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/chrome/common"
)

// Headers applies the iOS declaration while preserving explicit values.
var Headers = common.IOSHeaders

// BuildHeaders constructs the iOS identity and optional header positions.
func BuildHeaders(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	return common.BuildIOSHeaders(os)
}

// BuildRequestHeaders returns the retained iOS WebKit request declaration.
func BuildRequestHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.BuildIOSRequestHeaders(c)
}

// NavigationHeaders returns fresh iOS document-request defaults in wire order.
func NavigationHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.IOSNavigationHeaders(c)
}

// FetchHeaders returns fresh iOS renderer-request defaults in wire order.
func FetchHeaders(c profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.IOSFetchHeaders(c)
}
