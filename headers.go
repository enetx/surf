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
func (h Headers) Contains(header g.String, patterns any) bool {
	if h.Values(header) != nil {
		for _, value := range h.Values(header) {
			v := value.Lower()
			switch ps := patterns.(type) {
			case string:
				if v.Contains(g.String(ps).Lower()) {
					return true
				}
			case g.String:
				if v.Contains(ps.Lower()) {
					return true
				}
			case []string:
				if v.ContainsAny(g.TransformSlice(ps, g.NewString).Iter().Map(g.String.Lower).Collect()...) {
					return true
				}
			case g.Slice[string]:
				if v.ContainsAny(g.TransformSlice(ps, g.NewString).Iter().Map(g.String.Lower).Collect()...) {
					return true
				}
			case g.Slice[g.String]:
				if v.ContainsAny(ps.Iter().Map(g.String.Lower).Collect()...) {
					return true
				}
			case []*regexp.Regexp:
				if v.Regexp().MatchAny(ps...) {
					return true
				}
			}
		}
	}

	return false
}

// Values returns the values associated with a specified header key.
// It wraps the Values method from the textproto.MIMEHeader type.
func (h Headers) Values(key g.String) g.Slice[g.String] {
	return g.TransformSlice(textproto.MIMEHeader(h).Values(key.Std()), g.NewString)
}

// Get returns the first value associated with a specified header key.
// It wraps the Get method from the textproto.MIMEHeader type.
func (h Headers) Get(key g.String) g.String { return g.String(textproto.MIMEHeader(h).Get(key.Std())) }

// Del deletes the values associated with a specified header key.
// It wraps the Del method from the textproto.MIMEHeader type.
func (h Headers) Del(key g.String) { textproto.MIMEHeader(h).Del(key.Std()) }

// Clone returns a copy of Headers or nil if Headers is nil.
func (h Headers) Clone() Headers { return Headers(http.Header(h).Clone()) }
