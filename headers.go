package surf

import (
	"net/textproto"
	"regexp"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http"
)

// headers represents a collection of HTTP headers.
type headers http.Header

// Contains checks if the header contains any of the specified patterns.
// It accepts a header name and a pattern (or list of patterns) and returns a boolean value
// indicating whether any of the patterns are found in the header values.
// The patterns can be a string, a slice of strings, or a slice of *regexp.Regexp.
func (h headers) Contains(header string, patterns any) bool {
	if h.Values(header) != nil {
		for _, value := range h.Values(header) {
			v := g.String(value).Lower()
			switch ps := patterns.(type) {
			case string:
				if v.Contains(g.String(ps).Lower()) {
					return true
				}
			case []string:
				if v.ContainsAny(g.SliceMap(ps, g.NewString).Map(g.String.Lower)...) {
					return true
				}
			case []*regexp.Regexp:
				hs := g.SliceMap(ps, func(r *regexp.Regexp) g.String { return g.String(r.String()) })
				if v.ContainsRegexpAny(hs...).Ok() {
					return true
				}
			}
		}
	}

	return false
}

// Values returns the values associated with a specified header key.
// It wraps the Values method from the textproto.MIMEHeader type.
func (h headers) Values(key string) []string { return textproto.MIMEHeader(h).Values(key) }

// Get returns the first value associated with a specified header key.
// It wraps the Get method from the textproto.MIMEHeader type.
func (h headers) Get(key string) string { return textproto.MIMEHeader(h).Get(key) }
