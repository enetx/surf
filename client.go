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
	"mime/multipart"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

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
	mwMutex   sync.Mutex             // Mutex for thread-safe middleware operations
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
	c.mwMutex.Lock()
	defer c.mwMutex.Unlock()

	return c.reqMWs.run(req)
}

// applyRespMW applies all registered response middlewares to the given response in priority order.
// Middlewares are sorted by priority before execution, and processing stops on first error.
func (c *Client) applyRespMW(resp *Response) error {
	c.mwMutex.Lock()
	defer c.mwMutex.Unlock()

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

// Get creates a new HTTP GET request with the specified URL.
// Optional data parameter can be provided for query parameters.
func (c *Client) Get(rawURL g.String, data ...any) *Request {
	if len(data) != 0 {
		return c.buildRequest(rawURL, http.MethodGet, data[0])
	}

	return c.buildRequest(rawURL, http.MethodGet, nil)
}

// Delete creates a new HTTP DELETE request with the specified URL.
// Optional data parameter can be provided for request body.
func (c *Client) Delete(rawURL g.String, data ...any) *Request {
	if len(data) != 0 {
		return c.buildRequest(rawURL, http.MethodDelete, data[0])
	}

	return c.buildRequest(rawURL, http.MethodDelete, nil)
}

// Head creates a new HTTP HEAD request with the specified URL.
// HEAD requests are identical to GET but only return response headers.
func (c *Client) Head(rawURL g.String) *Request {
	return c.buildRequest(rawURL, http.MethodHead, nil)
}

// Post creates a new HTTP POST request with the specified URL and data.
// Data can be of various types (string, map, struct) and will be encoded appropriately.
func (c *Client) Post(rawURL g.String, data any) *Request {
	return c.buildRequest(rawURL, http.MethodPost, data)
}

// Put creates a new HTTP PUT request with the specified URL and data.
// PUT requests typically replace the entire resource at the specified URL.
func (c *Client) Put(rawURL g.String, data any) *Request {
	return c.buildRequest(rawURL, http.MethodPut, data)
}

// Patch creates a new HTTP PATCH request with the specified URL and data.
// PATCH requests typically apply partial modifications to a resource.
func (c *Client) Patch(rawURL g.String, data any) *Request {
	return c.buildRequest(rawURL, http.MethodPatch, data)
}

// FileUpload creates a new multipart file upload request.
// It uploads a file from filePath using the specified fieldName in the form.
// Optional data can include additional form fields (g.MapOrd) or custom reader (io.Reader).
func (c *Client) FileUpload(rawURL, fieldName, filePath g.String, data ...any) *Request {
	var (
		multipartData g.MapOrd[string, string]
		reader        io.Reader
		file          *os.File
		err           error
	)

	const maxDataLen = 2

	if len(data) > maxDataLen {
		data = data[:2]
	}

	for _, v := range data {
		switch i := v.(type) {
		case g.MapOrd[g.String, g.String]:
			mo := g.NewMapOrd[string, string](i.Len())
			i.Iter().ForEach(func(k, v g.String) { mo.Set(k.Std(), v.Std()) })
			multipartData = mo
		case g.MapOrd[string, string]:
			multipartData = i
		case string:
			reader = strings.NewReader(i)
		case g.String:
			reader = i.Reader()
		case io.Reader:
			reader = i
		}
	}

	request := new(Request)

	if reader == nil {
		file, err = os.Open(filePath.Std())
		if err != nil {
			request.err = err
			return request
		}

		reader = bufio.NewReader(file)
	}

	bodyReader, bodyWriter := io.Pipe()
	formWriter := multipart.NewWriter(bodyWriter)

	if c.boundary != nil {
		if err = formWriter.SetBoundary(c.boundary().Std()); err != nil {
			request.err = err
			return request
		}
	}

	var (
		errOnce  sync.Once
		writeErr error
	)

	setWriteErr := func(err error) {
		if err != nil {
			errOnce.Do(func() { writeErr = err })
		}
	}

	go func() {
		defer func() {
			if formWriter != nil {
				setWriteErr(formWriter.Close())
			}

			if bodyWriter != nil {
				setWriteErr(bodyWriter.Close())
			}

			if file != nil {
				setWriteErr(file.Close())
			}
		}()

		partWriter, err := formWriter.CreateFormFile(fieldName.Std(), filepath.Base(filePath.Std()))
		if err != nil {
			setWriteErr(err)
			return
		}

		if _, err = io.Copy(partWriter, reader); err != nil {
			setWriteErr(err)
			return
		}

		multipartData.Iter().
			Range(func(fieldname, value string) bool {
				if err = formWriter.WriteField(fieldname, value); err != nil {
					setWriteErr(err)
					return false
				}

				return true
			})
	}()

	req, err := http.NewRequest(http.MethodPost, rawURL.Std(), bodyReader)
	if err != nil {
		request.err = err
		return request
	}

	req.Header.Set(header.CONTENT_TYPE, formWriter.FormDataContentType())

	request.request = req
	request.cli = c
	request.werr = &writeErr

	return request
}

// Multipart creates a new multipart form data request with the specified form fields.
// The multipartData map contains field names and their corresponding values.
func (c *Client) Multipart(rawURL g.String, multipartData g.MapOrd[g.String, g.String]) *Request {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	if c.boundary != nil {
		if err := writer.SetBoundary(c.boundary().Std()); err != nil {
			request := new(Request)
			request.err = err
			return request
		}
	}

	request := new(Request)

	multipartData.Iter().
		Range(func(fieldname, value g.String) bool {
			formWriter, err := writer.CreateFormField(fieldname.Std())
			if err != nil {
				request.err = err
				return false
			}

			if _, err := io.Copy(formWriter, value.Reader()); err != nil {
				request.err = err
				return false
			}

			return true
		})

	if request.err != nil {
		return request
	}

	if err := writer.Close(); err != nil {
		request.err = err
		return request
	}

	req, err := http.NewRequest(http.MethodPost, rawURL.Std(), body)
	if err != nil {
		request.err = err
		return request
	}

	req.Header.Set(header.CONTENT_TYPE, writer.FormDataContentType())

	request.request = req
	request.cli = c

	return request
}

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

// buildRequest accepts a raw URL, a method type (like GET or POST), and data of any type.
// It formats the URL, builds the request body, and creates a new HTTP request with the specified
// method type and body.
// If there is an error, it returns a Request object with the error set.
func (c *Client) buildRequest(rawURL g.String, methodType string, data any) *Request {
	request := new(Request)

	body, contentType, err := buildBody(data)
	if err != nil {
		request.err = err
		return request
	}

	req, err := http.NewRequest(methodType, rawURL.Std(), body)
	if err != nil {
		request.err = err
		return request
	}

	if contentType != "" {
		req.Header.Add(header.CONTENT_TYPE, contentType)
	}

	request.request = req
	request.cli = c

	return request
}

// buildBody takes data of any type and, depending on its type, calls the appropriate method to
// build the request body.
// It returns an io.Reader, content type string, and an error if any.
func buildBody(data any) (io.Reader, string, error) {
	if data == nil {
		return nil, "", nil
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

	// if post encoded data aaa=bbb&ddd=ccc
	if contentType == "text/plain; charset=utf-8" && s.ContainsAnyChars("=&") {
		contentType = "application/x-www-form-urlencoded"
	}

	return s.Reader(), contentType, nil
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

// // sanitizeURL accepts a raw URL string and formats it to ensure it has an "http://" or "https://"
// // prefix.
// func sanitizeURL(rawURL g.String) string {
// 	rawURL = rawURL.TrimSet(".")
//
// 	if !rawURL.StartsWithAny("http://", "https://") {
// 		rawURL = rawURL.Prepend("http://")
// 	}
//
// 	return rawURL.Std()
// }

// parseURL attempts to parse any supported rawURL type into a *url.URL.
// Returns an error if the type is unsupported or if parsing fails.
func parseURL(rawURL g.String) g.Result[*url.URL] {
	if rawURL.Empty() {
		return g.Err[*url.URL](errors.New("URL is empty"))
	}

	parsedURL, err := url.Parse(rawURL.Std())
	if err != nil {
		return g.Err[*url.URL](fmt.Errorf("failed to parse URL '%s': %w", rawURL, err))
	}

	return g.Ok(parsedURL)
}
