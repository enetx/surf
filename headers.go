package surf

import (
	"net/textproto"
	"regexp"

	"github.com/enetx/g"
	"github.com/enetx/http"
)

// Headers represents a collection of HTTP Headers.
type Headers http.Header

// Contains checks if the header contains any of the specified patterns.
// It accepts a header name and a pattern (or list of patterns) and returns a boolean value
// indicating whether any of the patterns are found in the header values.
// The patterns can be a string, a slice of strings, or a slice of *regexp.Regexp.
func (h Headers) Contains(header string, patterns any) bool {
	if h.Values(header) != nil {
		for _, value := range h.Values(header) {
			v := g.String(value).Lower()
			switch ps := patterns.(type) {
			case string:
				if v.Contains(g.String(ps).Lower()) {
					return true
				}
			case []string:
				if v.ContainsAny(g.SliceMap(ps, g.NewString).Iter().Map(g.String.Lower).Collect()...) {
					return true
				}
			case []*regexp.Regexp:
				hs := g.SliceMap(ps, func(r *regexp.Regexp) g.String { return g.String(r.String()) })
				if r := v.ContainsRegexpAny(hs...); r.IsOk() && r.Ok() {
					return true
				}
			}
		}
	}

	return false
}

// Values returns the values associated with a specified header key.
// It wraps the Values method from the textproto.MIMEHeader type.
func (h Headers) Values(key string) []string { return textproto.MIMEHeader(h).Values(key) }

// Get returns the first value associated with a specified header key.
// It wraps the Get method from the textproto.MIMEHeader type.
func (h Headers) Get(key string) string { return textproto.MIMEHeader(h).Get(key) }
