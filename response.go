package surf

import (
	"net"
	"net/url"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/surf/header"
)

// Response represents a custom response structure.
type Response struct {
	*Client                      // Client is the associated client for the response.
	remoteAddr    net.Addr       // Remote network address.
	URL           *url.URL       // URL of the response.
	response      *http.Response // Underlying http.Response.
	Body          *Body          // Response body.
	request       *Request       // Corresponding request.
	Headers       Headers        // Response headers.
	UserAgent     string         // User agent string.
	Proto         string         // HTTP protocol version.
	Cookies       Cookies        // Response cookies.
	Time          time.Duration  // Total time taken for the response.
	ContentLength int64          // Length of the response content.
	StatusCode    StatusCode     // HTTP status code.
	Attempts      int            // Number of attempts made.
}

// newResponse creates a new Response instance from the response pool.
func newResponse() *Response { return responsePool.Get().(*Response) }

// Release releases the Response object back to the response pool.
func (resp *Response) Release() {
	resp.reset()
	responsePool.Put(resp)
}

// reset resets the fields of the Response instance to their default values or nil.
func (resp *Response) reset() {
	// Release and reset the body
	resp.Body.release()
	resp.Body = nil

	// Release and reset the request
	resp.request.release()
	resp.request = nil

	// Reset other fields
	resp.remoteAddr = nil
	resp.URL = nil
	resp.response = nil
	resp.Headers = nil
	resp.UserAgent = ""
	resp.Proto = ""
	resp.Cookies = nil
	resp.Time = 0
	resp.ContentLength = 0
	resp.StatusCode = 0
	resp.Attempts = 0
}

// GetResponse returns the underlying http.Response of the custom response.
func (resp Response) GetResponse() *http.Response { return resp.response }

// Referer returns the referer of the response.
func (resp Response) Referer() string { return resp.response.Request.Referer() }

// Location returns the location of the response.
func (resp Response) Location() string { return resp.Headers.Get(header.LOCATION) }

// GetCookies returns the cookies from the response for the given URL.
func (resp Response) GetCookies(rawURL string) []*http.Cookie { return resp.getCookies(rawURL) }

// RemoteAddress returns the remote address of the response.
func (resp Response) RemoteAddress() net.Addr { return resp.remoteAddr }

// SetCookies sets cookies for the given URL in the response.
func (resp *Response) SetCookies(rawURL string, cookies []*http.Cookie) error {
	return resp.setCookies(rawURL, cookies)
}

// TLSGrabber returns a tlsData struct containing information about the TLS connection if it
// exists.
func (resp Response) TLSGrabber() *tlsData {
	if resp.response.TLS != nil {
		return tlsGrabber(resp.response.TLS)
	}

	return nil
}
