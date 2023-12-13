package surf

import (
	"net"
	"net/url"
	"time"

	"gitlab.com/x0xO/http"
)

// Response represents a custom response structure.
type Response struct {
	*Client                      // Client is the associated client for the response.
	remoteAddr    net.Addr       // Remote network address.
	URL           *url.URL       // URL of the response.
	response      *http.Response // Underlying http.Response.
	Body          *body          // Response body.
	request       *Request       // Corresponding request.
	Headers       headers        // Response headers.
	Status        string         // HTTP status string.
	UserAgent     string         // User agent string.
	Proto         string         // HTTP protocol version.
	Cookies       cookies        // Response cookies.
	Time          time.Duration  // Total time taken for the response.
	ContentLength int64          // Length of the response content.
	StatusCode    int            // HTTP status code.
	Attempts      int            // Number of attempts made.
}

// GetResponse returns the underlying http.Response of the custom response.
func (resp Response) GetResponse() *http.Response { return resp.response }

// Referer returns the referer of the response.
func (resp Response) Referer() string { return resp.response.Request.Referer() }

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
