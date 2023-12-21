package surf

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http"
)

// Client struct provides a customizable HTTP client with configurable options for making requests,
// handling connections, and managing TLS settings.
type Client struct {
	cli       *http.Client         // Standard HTTP client.
	dialer    *net.Dialer          // Network dialer.
	opt       *Options             // Client options.
	transport http.RoundTripper    // HTTP transport settings.
	tlsConfig *tls.Config          // TLS configuration.
	reqMW     []requestMiddleware  // Request middleware functions.
	respMW    []responseMiddleware // Response middleware functions.
}

// NewClient creates a new Client with default settings.
func NewClient() *Client {
	return new(Client).
		ClientMiddleware(defaultDialerMW).
		ClientMiddleware(defaultTLSConfigMW).
		ClientMiddleware(defaultTransportMW).
		ClientMiddleware(defaultClientMW).
		ClientMiddleware(redirectPolicyMW).
		RequestMiddleware(defaultUserAgentMW).
		RequestMiddleware(got101ResponseMW).
		ResponseMiddleware(webSocketUpgradeErrorMW).
		ResponseMiddleware(decodeBodyMW)
}

// ClientMiddleware add a client middleware.
func (c *Client) ClientMiddleware(m clientMiddleware) *Client { m(c); return c }

// RequestMiddleware add a request middleware which hooks before request sent.
func (c *Client) RequestMiddleware(m requestMiddleware) *Client {
	c.reqMW = append(c.reqMW, m)
	return c
}

// ResponseMiddleware add a response middleware which hooks after response received.
func (c *Client) ResponseMiddleware(m responseMiddleware) *Client {
	c.respMW = append(c.respMW, m)
	return c
}

// CloseIdleConnections removes all entries from the cached transports.
// Specifically used when Singleton is enabled for JA3 or Impersonate functionalities.
func (c *Client) CloseIdleConnections() {
	if c.opt == nil || !c.opt.singleton {
		return
	}

	c.cli.CloseIdleConnections()
}

// GetClient returns http.Client used by the Client.
func (c *Client) GetClient() *http.Client { return c.cli }

// GetDialer returns the net.Dialer used by the Client.
func (c *Client) GetDialer() *net.Dialer { return c.dialer }

// GetTransport returns the http.transport used by the Client.
func (c *Client) GetTransport() http.RoundTripper { return c.transport }

// GetTLSConfig returns the tls.Config used by the Client.
func (c *Client) GetTLSConfig() *tls.Config { return c.tlsConfig }

// SetOptions sets the provided options for the client and returns the updated client.
// It configures various settings like HTTP2, sessions, keep-alive, dial TLS, resolver,
// interface address, timeout, and redirect policy.
func (c *Client) SetOptions(opt *Options) *Client {
	c.opt = opt
	c.opt.dialer = c.dialer

	// sorting client middleware by priority
	c.opt.cliMW.SortBy(func(i, j int) bool { return (*c.opt.cliMW)[i].Key < (*c.opt.cliMW)[j].Key })
	c.opt.cliMW.ForEach(func(_ int, m clientMiddleware) { c.ClientMiddleware(m) })

	return c
}

// Raw creates a new HTTP request using the provided raw data and scheme.
// The raw parameter should contain the raw HTTP request data as a string.
// The scheme parameter specifies the scheme (e.g., http, https) for the request.
func (c *Client) Raw(raw, scheme string) *Request {
	request := new(Request)

	req, err := http.ReadRequest(bufio.NewReader(g.String(raw).TrimSpace().Add("\n\n").Reader()))
	if err != nil {
		request.error = err
		return request
	}

	req.RequestURI, req.URL.Scheme, req.URL.Host = "", scheme, req.Host

	request.request = req
	request.client = c

	return request
}

// Get creates a new GET request.
func (c *Client) Get(rawURL string, data ...any) *Request {
	if len(data) != 0 {
		return c.buildRequest(rawURL, http.MethodGet, data[0])
	}

	return c.buildRequest(rawURL, http.MethodGet, nil)
}

// Delete creates a new DELETE request.
func (c *Client) Delete(rawURL string, data ...any) *Request {
	if len(data) != 0 {
		return c.buildRequest(rawURL, http.MethodDelete, data[0])
	}

	return c.buildRequest(rawURL, http.MethodDelete, nil)
}

// Head creates a new HEAD request.
func (c *Client) Head(rawURL string) *Request {
	return c.buildRequest(rawURL, http.MethodHead, nil)
}

// Post creates a new POST request.
func (c *Client) Post(rawURL string, data any) *Request {
	return c.buildRequest(rawURL, http.MethodPost, data)
}

// Put creates a new PUT request.
func (c *Client) Put(rawURL string, data any) *Request {
	return c.buildRequest(rawURL, http.MethodPut, data)
}

// Patch creates a new PATCH request.
func (c *Client) Patch(rawURL string, data any) *Request {
	return c.buildRequest(rawURL, http.MethodPatch, data)
}

// FileUpload creates a new multipart file upload request.
func (c *Client) FileUpload(rawURL, fieldName, filePath string, data ...any) *Request {
	rawURL = urlFormatter(rawURL)

	var (
		multipartValues map[string]string
		reader          io.Reader
		file            *os.File
		err             error
	)

	const maxDataLen = 2

	if len(data) > maxDataLen {
		data = data[:2]
	}

	for _, v := range data {
		switch i := v.(type) {
		case map[string]string:
			multipartValues = i
		case g.Map[string, string]:
			multipartValues = i
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
		file, err = os.Open(filePath)
		if err != nil {
			request.error = err
			return request
		}

		reader = bufio.NewReader(file)
	}

	bodyReader, bodyWriter := io.Pipe()
	formWriter := multipart.NewWriter(bodyWriter)

	var errOnce sync.Once

	writeErr := errors.New("")

	setWriteErr := func(err error) {
		if err != nil {
			errOnce.Do(func() { writeErr = err })
		}
	}

	go func() {
		defer file.Close()

		partWriter, err := formWriter.CreateFormFile(fieldName, filepath.Base(filePath))
		setWriteErr(err)

		_, err = io.Copy(partWriter, reader)
		setWriteErr(err)

		// https://staticcheck.io/docs/checks#S1031
		for field, value := range multipartValues {
			_ = formWriter.WriteField(field, value)
		}

		setWriteErr(formWriter.Close())
		setWriteErr(bodyWriter.Close())
	}()

	req, err := http.NewRequest(http.MethodPost, rawURL, bodyReader)
	if err != nil {
		request.error = err
		return request
	}

	req.Header.Set("Content-Type", formWriter.FormDataContentType())

	request.request = req
	request.client = c
	request.writeErr = &writeErr

	return request
}

// Multipart creates a new multipart form data request.
func (c *Client) Multipart(rawURL string, multipartValues map[string]string) *Request {
	rawURL = urlFormatter(rawURL)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	request := new(Request)

	for field, value := range multipartValues {
		formWriter, err := writer.CreateFormField(field)
		if err != nil {
			request.error = err
			return request
		}

		if _, err := io.Copy(formWriter, strings.NewReader(value)); err != nil {
			request.error = err
			return request
		}
	}

	if err := writer.Close(); err != nil {
		request.error = err
		return request
	}

	req, err := http.NewRequest(http.MethodPost, rawURL, body)
	if err != nil {
		request.error = err
		return request
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	request.request = req
	request.client = c

	return request
}

// getCookies returns cookies for the specified URL.
func (c Client) getCookies(rawURL string) []*http.Cookie {
	if c.cli.Jar == nil {
		return nil
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	return c.cli.Jar.Cookies(parsedURL)
}

// setCookies sets cookies for the specified URL.
func (c *Client) setCookies(rawURL string, cookies []*http.Cookie) error {
	if c.cli.Jar == nil {
		return errors.New("cookie jar is not available")
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	c.cli.Jar.SetCookies(parsedURL, cookies)

	return nil
}

// buildRequest accepts a raw URL, a method type (like GET or POST), and data of any type.
// It formats the URL, builds the request body, and creates a new HTTP request with the specified
// method type and body.
// If there is an error, it returns a Request object with the error set.
func (c *Client) buildRequest(rawURL, methodType string, data any) *Request {
	rawURL = urlFormatter(rawURL)

	request := new(Request)

	body, contentType, err := buildBody(data)
	if err != nil {
		request.error = err
		return request
	}

	req, err := http.NewRequest(methodType, rawURL, body)
	if err != nil {
		request.error = err
		return request
	}

	if contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}

	request.request = req
	request.client = c

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
		return buildStringBody(d.Std())
	case map[string]string:
		return buildMapBody(d)
	case g.Map[string, string]:
		return buildMapBody(d)
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
func buildStringBody(data string) (io.Reader, string, error) {
	contentType := detectContentType(data)

	// if post encoded data aaa=bbb&ddd=ccc
	if contentType == "text/plain; charset=utf-8" && strings.ContainsAny(data, "=&") {
		contentType = "application/x-www-form-urlencoded"
	}

	reader := strings.NewReader(data)

	return reader, contentType, nil
}

// detectContentType takes a string and returns the content type of the data by checking if it's a
// JSON or XML string.
func detectContentType(data string) string {
	var v any

	if json.Unmarshal([]byte(data), &v) == nil {
		return "application/json; charset=utf-8"
	} else if xml.Unmarshal([]byte(data), &v) == nil {
		return "application/xml; charset=utf-8"
	}

	// other types like pdf etc..
	return http.DetectContentType([]byte(data))
}

// buildMapBody accepts a map of string keys and values, and returns an io.Reader, content type
// string, and an error if any.
// It converts the map to a URL-encoded string and creates a strings.Reader from it.
func buildMapBody(data map[string]string) (io.Reader, string, error) {
	// post data map[string]string{"aaa": "bbb", "ddd": "ccc"}
	contentType := "application/x-www-form-urlencoded"
	form := url.Values{}

	for key, value := range data {
		form.Add(key, value)
	}

	reader := g.String(form.Encode()).Reader()

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
	value := reflect.ValueOf(data)

	for i := 0; i < value.Type().NumField(); i++ {
		field := value.Type().Field(i)

		if _, ok := field.Tag.Lookup("json"); ok {
			return "json"
		}

		if _, ok := field.Tag.Lookup("xml"); ok {
			return "xml"
		}
	}

	return ""
}

// urlFormatter accepts a raw URL string and formats it to ensure it has an "http://" or "https://"
// prefix.
func urlFormatter(rawURL string) string {
	_url := g.String(rawURL).Trim(".")

	if !_url.StartsWith("http://", "https://") {
		_url = _url.AddPrefix("http://")
	}

	return _url.Std()
}
