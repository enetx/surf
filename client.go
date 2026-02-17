// Package surf provides a comprehensive HTTP client library with advanced features
// for web scraping, automation, and HTTP/3 support with various browser fingerprinting capabilities.
package surf

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"strings"
	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
)

// Client represents a highly configurable HTTP client with middleware support,
// advanced transport options (HTTP/1.1, HTTP/2, HTTP/3), proxy handling,
// TLS fingerprinting, and comprehensive request/response processing capabilities.
type Client struct {
	cli       *http.Client           // Standard HTTP client for actual requests
	dialer    *net.Dialer            // Network dialer with optional custom DNS resolver
	builder   *Builder               // Associated builder for configuration
	transport http.RoundTripper      // HTTP transport (can be HTTP/1.1, HTTP/2, or HTTP/3)
	tlsConfig *tls.Config            // TLS configuration for secure connections
	reqMWs    *middleware[*Request]  // Priority-ordered request middlewares
	respMWs   *middleware[*Response] // Priority-ordered response middlewares
	boundary  func() g.String        // Custom boundary generator for multipart requests
}

// NewClient creates a new Client with sensible default settings including
// default dialer, TLS configuration, HTTP transport, and basic middleware.
func NewClient() *Client {
	cli := &Client{
		reqMWs:  newMiddleware[*Request](),
		respMWs: newMiddleware[*Response](),
	}

	defaultDialerMW(cli)
	defaultTLSConfigMW(cli)
	defaultTransportMW(cli)
	defaultClientMW(cli)
	redirectPolicyMW(cli)

	cli.reqMWs.add(0, defaultUserAgentMW)
	cli.reqMWs.add(0, got101ResponseMW)

	cli.respMWs.add(0, webSocketUpgradeErrorMW)
	cli.respMWs.add(0, decodeBodyMW)

	return cli
}

// applyReqMW applies all registered request middlewares to the given request in priority order.
// Middlewares are sorted by priority before execution, and processing stops on first error.
func (c *Client) applyReqMW(req *Request) error {
	return c.reqMWs.run(req)
}

// applyRespMW applies all registered response middlewares to the given response in priority order.
// Middlewares are sorted by priority before execution, and processing stops on first error.
func (c *Client) applyRespMW(resp *Response) error {
	return c.respMWs.run(resp)
}

// CloseIdleConnections closes idle connections while keeping the client usable.
// Safe to call periodically to free resources during long-running operations.
func (c *Client) CloseIdleConnections() { c.cli.CloseIdleConnections() }

// Close completely shuts down the client and releases all resources.
// After calling Close, the client should not be used.
func (c *Client) Close() error {
	if closer, ok := c.transport.(interface{ Close() error }); ok {
		return closer.Close()
	}

	c.CloseIdleConnections()
	return nil
}

// GetClient returns http.Client used by the Client.
func (c *Client) GetClient() *http.Client { return c.cli }

// GetDialer returns the net.Dialer used by the Client.
func (c *Client) GetDialer() *net.Dialer { return c.dialer }

// GetTransport returns the http.transport used by the Client.
func (c *Client) GetTransport() http.RoundTripper { return c.transport }

// GetTLSConfig returns the tls.Config used by the Client.
func (c *Client) GetTLSConfig() *tls.Config { return c.tlsConfig }

// Builder returns a new Builder instance associated with this client.
// The builder allows for method chaining to configure various client options.
func (c *Client) Builder() *Builder {
	c.builder = &Builder{cli: c, cliMWs: newMiddleware[*Client]()}
	return c.builder
}

// Raw creates a new HTTP request using the provided raw data and scheme.
// The raw parameter should contain the raw HTTP request data as a string.
// The scheme parameter specifies the scheme (e.g., http, https) for the request.
func (c *Client) Raw(raw, scheme g.String) *Request {
	request := new(Request)

	req, err := http.ReadRequest(bufio.NewReader(raw.Trim().Append("\n\n").Reader()))
	if err != nil {
		request.err = err
		return request
	}

	req.RequestURI, req.URL.Scheme, req.URL.Host = "", scheme.Std(), req.Host

	request.request = req
	request.cli = c

	return request
}

// Get creates a new HTTP GET request for the specified URL.
// GET requests are used to retrieve data from a server.
func (c *Client) Get(rawURL g.String) *Request { return c.newRequest(http.MethodGet, rawURL) }

// Delete creates a new HTTP DELETE request for the specified URL.
// DELETE requests are used to remove a resource from a server.
func (c *Client) Delete(rawURL g.String) *Request { return c.newRequest(http.MethodDelete, rawURL) }

// Head creates a new HTTP HEAD request for the specified URL.
// HEAD requests are identical to GET but without the response body.
func (c *Client) Head(rawURL g.String) *Request { return c.newRequest(http.MethodHead, rawURL) }

// Post creates a new HTTP POST request for the specified URL.
// POST requests are used to submit data to a server.
func (c *Client) Post(rawURL g.String) *Request { return c.newRequest(http.MethodPost, rawURL) }

// Put creates a new HTTP PUT request for the specified URL.
// PUT requests are used to replace a resource on a server.
func (c *Client) Put(rawURL g.String) *Request { return c.newRequest(http.MethodPut, rawURL) }

// Patch creates a new HTTP PATCH request for the specified URL.
// PATCH requests are used to apply partial modifications to a resource.
func (c *Client) Patch(rawURL g.String) *Request { return c.newRequest(http.MethodPatch, rawURL) }

// Options creates a new HTTP OPTIONS request for the specified URL.
// OPTIONS requests are used to describe the communication options for a resource.
func (c *Client) Options(rawURL g.String) *Request { return c.newRequest(http.MethodOptions, rawURL) }

// Connect creates a new HTTP CONNECT request for the specified URL.
// CONNECT requests are used to establish a tunnel to the server.
func (c *Client) Connect(rawURL g.String) *Request { return c.newRequest(http.MethodConnect, rawURL) }

// Trace creates a new HTTP TRACE request for the specified URL.
// TRACE requests are used to perform a message loop-back test along the path to the target resource.
func (c *Client) Trace(rawURL g.String) *Request { return c.newRequest(http.MethodTrace, rawURL) }

// getCookies returns cookies for the specified URL.
func (c *Client) getCookies(rawURL g.String) []*http.Cookie {
	if c.cli.Jar == nil {
		return nil
	}

	parsedURL := parseURL(rawURL)
	if parsedURL.IsErr() {
		return nil
	}

	return c.cli.Jar.Cookies(parsedURL.Ok())
}

// setCookies sets cookies for the specified URL.
func (c *Client) setCookies(rawURL g.String, cookies []*http.Cookie) error {
	if c.cli.Jar == nil {
		return errors.New("cookie jar is not available")
	}

	parsedURL := parseURL(rawURL)
	if parsedURL.IsErr() {
		return parsedURL.Err()
	}

	c.cli.Jar.SetCookies(parsedURL.Ok(), cookies)

	return nil
}

// newRequest creates a new Request with the specified HTTP method and URL.
// It initializes the underlying http.Request and associates it with this client.
func (c *Client) newRequest(method string, rawURL g.String) *Request {
	request := new(Request)

	req, err := http.NewRequest(method, rawURL.Std(), nil)
	if err != nil {
		request.err = err
		return request
	}

	request.request = req
	request.cli = c
	return request
}

// Body sets the request body from various data types.
// Supported types include: []byte, string, g.String, g.Bytes, map[string]string,
// g.Map, g.MapOrd, and structs with json/xml tags.
// The Content-Type header is automatically detected and set based on the data.
// Returns the request for method chaining.
func (req *Request) Body(data any) *Request {
	if req.err != nil {
		return req
	}

	if data == nil {
		return req
	}

	body, contentType, err := buildBody(data)
	if err != nil {
		req.err = err
		return req
	}

	n := int64(-1)

	switch v := body.(type) {
	case *bytes.Reader:
		n = int64(v.Len())
	case *strings.Reader:
		n = int64(v.Len())
	case *bytes.Buffer:
		n = int64(v.Len())
	}

	req.request.ContentLength = n

	if n == 0 {
		req.request.Body = http.NoBody
	} else {
		if rc, ok := body.(io.ReadCloser); ok {
			req.request.Body = rc
		} else {
			req.request.Body = io.NopCloser(body)
		}
	}

	if contentType != "" {
		req.request.Header.Set(header.CONTENT_TYPE, contentType)
	}

	return req
}

// buildBody takes data of any type and, depending on its type, calls the appropriate method to
// build the request body.
// It returns an io.Reader, content type string, and an error if any.
func buildBody(data any) (io.Reader, string, error) {
	if data == nil {
		return nil, "", nil
	}

	if r, ok := data.(io.Reader); ok {
		return r, "", nil
	}

	switch d := data.(type) {
	case []byte:
		return buildByteBody(d)
	case g.Bytes:
		return buildByteBody(d)
	case string:
		return buildStringBody(d)
	case g.String:
		return buildStringBody(d)
	case map[string]string:
		return buildMapBody(d)
	case g.Map[string, string]:
		return buildMapBody(d)
	case g.Map[g.String, g.String]:
		return buildMapBody(d)
	case g.MapOrd[g.String, g.String]:
		return buildMapOrdBody(d)
	case g.MapOrd[string, string]:
		return buildMapOrdBody(d)
	default:
		return buildAnnotatedBody(data)
	}
}

// buildByteBody accepts a byte slice and returns an io.Reader, content type string, and an error
// if any.
// It detects the content type of the data and creates a bytes.Reader from the data.
func buildByteBody(data []byte) (io.Reader, string, error) {
	// raw data
	contentType := http.DetectContentType(data)
	reader := bytes.NewReader(data)

	return reader, contentType, nil
}

// buildStringBody accepts a string and returns an io.Reader, content type string, and an error if
// any.
// It detects the content type of the data and creates a strings.Reader from the data.
func buildStringBody[T ~string](data T) (io.Reader, string, error) {
	s := g.String(data)

	contentType := detectContentType(s.Bytes())

	if contentType == "text/plain; charset=utf-8" && isFormEncoded(s) {
		contentType = "application/x-www-form-urlencoded"
	}

	return s.Reader(), contentType, nil
}

// isFormEncoded checks if a string looks like valid URL-encoded form data.
// It verifies that the string consists of key=value pairs separated by &,
// where keys and values are non-empty and contain no whitespace.
func isFormEncoded(s g.String) bool {
	if s.IsEmpty() || !s.Contains("=") {
		return false
	}

	pairs := s.Split("&")

	for pair := range pairs {
		if pair.IsEmpty() {
			return false
		}

		eq := pair.IndexRune('=')
		if eq.Lte(0) {
			return false
		}

		if pair.ContainsAny(" \t\n\r") {
			return false
		}
	}

	return true
}

// detectContentType takes a string and returns the content type of the data by checking if it's a
// JSON or XML string.
func detectContentType(data []byte) string {
	var v any

	if json.Unmarshal(data, &v) == nil {
		return "application/json; charset=utf-8"
	} else if xml.Unmarshal(data, &v) == nil {
		return "application/xml; charset=utf-8"
	}

	// other types like pdf etc..
	return http.DetectContentType(data)
}

// buildMapBody accepts a map of string keys and values, and returns an io.Reader, content type
// string, and an error if any.
// It converts the map to a URL-encoded string and creates a strings.Reader from it.
func buildMapBody[T ~string, M ~map[T]T](m M) (io.Reader, string, error) {
	// post data map[string]string{"aaa": "bbb", "ddd": "ccc"}
	contentType := "application/x-www-form-urlencoded"
	form := make(url.Values)

	for key, value := range m {
		form.Add(string(key), string(value))
	}

	reader := g.String(form.Encode()).Reader()

	return reader, contentType, nil
}

// buildMapOrdBody takes an ordered map with string keys and values (g.MapOrd[T, T])
// and returns an io.Reader, a content type string, and an error if any.
// It encodes the map as an application/x-www-form-urlencoded string
// and creates a strings.Reader from the result.
//
// This is useful for building HTTP POST request bodies while preserving field order.
func buildMapOrdBody[T ~string](m g.MapOrd[T, T]) (io.Reader, string, error) {
	contentType := "application/x-www-form-urlencoded"

	var buf strings.Builder

	m.Iter().ForEach(func(key, value T) {
		if buf.Len() > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(url.QueryEscape(string(key)))
		buf.WriteByte('=')
		buf.WriteString(url.QueryEscape(string(value)))
	})

	reader := strings.NewReader(buf.String())

	return reader, contentType, nil
}

// buildAnnotatedBody accepts data of any type and returns an io.Reader, content type string, and
// an error if any. It detects the data format by checking the struct tags and encodes the data in
// the corresponding format (JSON or XML).
func buildAnnotatedBody(data any) (io.Reader, string, error) {
	var buf bytes.Buffer

	switch detectAnnotatedDataType(data) {
	case "json":
		if json.NewEncoder(&buf).Encode(data) == nil {
			return &buf, "application/json; charset=utf-8", nil
		}
	case "xml":
		if xml.NewEncoder(&buf).Encode(data) == nil {
			return &buf, "application/xml; charset=utf-8", nil
		}
	}

	return nil, "", errors.New("data type not detected")
}

// detectAnnotatedDataType takes data of any type and returns the data format as a string (either
// "json" or "xml") by checking the struct tags.
func detectAnnotatedDataType(data any) string {
	t := reflect.TypeOf(data)
	if t == nil {
		return ""
	}

	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return ""
	}

	for i := range t.NumField() {
		tag := t.Field(i).Tag

		if _, ok := tag.Lookup("json"); ok {
			return "json"
		}

		if _, ok := tag.Lookup("xml"); ok {
			return "xml"
		}
	}

	return ""
}

// parseURL attempts to parse any supported rawURL type into a *url.URL.
// Returns an error if the type is unsupported or if parsing fails.
func parseURL(rawURL g.String) g.Result[*url.URL] {
	if rawURL.IsEmpty() {
		return g.Err[*url.URL](errors.New("URL is empty"))
	}

	parsedURL, err := url.Parse(rawURL.Std())
	if err != nil {
		return g.Err[*url.URL](fmt.Errorf("failed to parse URL '%s': %w", rawURL, err))
	}

	return g.Ok(parsedURL)
}
