package surf

import (
	"net"
	"net/url"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
)

// Response represents an HTTP response with enhanced functionality and metadata.
// It wraps the standard http.Response and provides additional features like timing information,
// retry attempts tracking, enhanced cookie management, and convenient access methods.
type Response struct {
	Headers       Headers        // Response headers with convenience methods
	Cookies       Cookies        // Response cookies with enhanced functionality
	UserAgent     g.String       // User agent that was used for the request
	Proto         g.String       // HTTP protocol version (HTTP/1.1, HTTP/2, HTTP/3)
	remoteAddr    net.Addr       // Remote server address captured during connection
	*Client                      // Embedded client provides access to all client functionality
	URL           *url.URL       // Final URL after following redirects
	response      *http.Response // Underlying standard HTTP response
	Body          *Body          // Enhanced response body with compression support and caching
	request       *Request       // The original request that generated this response
	Time          time.Duration  // Total request duration including retries
	ContentLength int64          // Content-Length header value (-1 if not specified)
	StatusCode    StatusCode     // HTTP status code with convenience methods
	Attempts      int            // Number of retry attempts made for this request
}

// GetResponse returns the underlying standard http.Response.
// Provides access to the wrapped HTTP response for advanced use cases.
func (resp Response) GetResponse() *http.Response { return resp.response }

// Referer returns the HTTP Referer header value from the original request.
// This indicates which page linked to the resource being requested.
func (resp Response) Referer() g.String { return g.String(resp.response.Request.Referer()) }

// Location returns the HTTP Location header value, typically used in redirects.
// Contains the URL that the client should redirect to for 3xx status codes.
func (resp Response) Location() g.String { return resp.Headers.Get(header.LOCATION) }

// GetCookies returns all cookies from the response that would be sent to the specified URL.
// Filters cookies based on domain, path, and security attributes.
func (resp Response) GetCookies(rawURL g.String) []*http.Cookie { return resp.getCookies(rawURL) }

// RemoteAddress returns the network address of the server that sent this response.
// Useful for logging, debugging, or connection analysis.
func (resp Response) RemoteAddress() net.Addr { return resp.remoteAddr }

// SetCookies stores cookies in the client's cookie jar for the specified URL.
// This allows the cookies to be automatically sent with future requests to matching URLs.
func (resp *Response) SetCookies(rawURL g.String, cookies []*http.Cookie) error {
	return resp.setCookies(rawURL, cookies)
}

// TLSGrabber extracts TLS connection information from the response.
// Returns detailed TLS connection data including certificates, cipher suites, and protocol version
// if the response was received over a TLS connection. Returns nil for non-TLS connections.
func (resp Response) TLSGrabber() *TLSData {
	if resp.response.TLS != nil {
		return tlsGrabber(resp.response.TLS)
	}

	return nil
}
