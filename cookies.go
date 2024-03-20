package surf

import (
	"regexp"

	"github.com/enetx/g"
	"github.com/enetx/http"
)

// cookies represents a list of HTTP cookies.
type cookies []*http.Cookie

// Contains checks if the cookies collection contains a cookie that matches the provided pattern.
// The pattern parameter can be either a string or a pointer to a regexp.Regexp object.
// The method returns true if a matching cookie is found and false otherwise.
func (cs *cookies) Contains(pattern any) bool {
	for _, cookie := range *cs {
		c := g.String(cookie.String()).Lower()
		switch p := pattern.(type) {
		case string:
			if c.Contains(g.String(p).Lower()) {
				return true
			}
		case *regexp.Regexp:
			if c.ContainsRegexp(g.String(p.String())).Ok() {
				return true
			}
		}
	}

	return false
}
