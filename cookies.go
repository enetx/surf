package surf

import (
	"regexp"

	"github.com/enetx/g"
	"github.com/enetx/http"
)

// Cookies represents a list of HTTP Cookies.
type Cookies []*http.Cookie

// Contains checks if the cookies collection contains a cookie that matches the provided pattern.
// The pattern parameter can be either a string or a pointer to a regexp.Regexp object.
// The method returns true if a matching cookie is found and false otherwise.
func (cs Cookies) Contains(pattern any) bool {
	for _, cookie := range cs {
		c := g.String(cookie.String()).Lower()
		switch p := pattern.(type) {
		case string:
			if c.Contains(g.String(p).Lower()) {
				return true
			}
		case g.String:
			if c.Contains(p.Lower()) {
				return true
			}
		case *regexp.Regexp:
			if c.Regexp().Match(p) {
				return true
			}
		}
	}

	return false
}
