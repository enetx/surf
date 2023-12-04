package surf

import (
	"net/url"

	"gitlab.com/x0xO/http"
)

// history represents a list of HTTP responses used for response history tracking.
type history []*http.Response

// URLS retrieves the URLs from the HTTP response history.
// It returns a slice of pointers to url.URL.
func (his history) URLS() []*url.URL {
	var urls []*url.URL

	for _, h := range his {
		if h.Request.URL != nil {
			urls = append(urls, h.Request.URL)
		}
	}

	return urls
}

// Referrers retrieves the referrers from the HTTP response history.
// It returns a slice of strings containing the referrers.
func (his history) Referrers() []string {
	var referrers []string

	for _, h := range his {
		if h.Request.Referer() != "" {
			referrers = append(referrers, h.Request.Referer())
		}
	}

	return referrers
}

// StatusCodes retrieves the status codes from the HTTP response history.
// It returns a slice of integers containing the status codes.
func (his history) StatusCodes() []int {
	statusCodes := make([]int, 0, len(his))

	for _, h := range his {
		statusCodes = append(statusCodes, h.StatusCode)
	}

	return statusCodes
}

// Cookies retrieves the cookies from the HTTP response history.
// It returns a slice of slices of pointers to http.Cookie.
func (his history) Cookies() [][]*http.Cookie {
	var cookies [][]*http.Cookie

	for _, h := range his {
		if len(h.Cookies()) != 0 {
			cookies = append(cookies, h.Cookies())
		}
	}

	return cookies
}
