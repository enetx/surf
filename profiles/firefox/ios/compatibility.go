package ios

import (
	"github.com/enetx/g"
	"github.com/enetx/surf/profiles"
	"github.com/enetx/surf/profiles/firefox/common"
)

// Headers applies the Firefox 148 iOS placeholder preset to an ordered map.
var Headers = common.IOSHeaders

// BuildHeaders constructs the unchanged iOS identity fragment.
func BuildHeaders(os profiles.OSKey) *g.MapOrd[g.String, g.String] {
	return common.BuildMobileHeaders(os)
}

// BuildRequestHeaders returns fresh Firefox 148 iOS placeholder headers.
// It shares the existing mobile header template, not desktop 160 policy.
func BuildRequestHeaders(ctx profiles.HeaderContext) g.MapOrd[g.String, g.String] {
	return common.BuildPlaceholderRequestHeaders(ctx)
}
