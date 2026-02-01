package surf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/internal/drainbody"
	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/profiles/firefox"
)

// Request represents an HTTP request with additional surf-specific functionality.
// It wraps the standard http.Request and provides enhanced features like middleware support,
// retry capabilities, remote address tracking, and structured error handling.
type Request struct {
	err        error         // General error associated with the request (validation, setup, etc.)
	remoteAddr net.Addr      // Remote server address captured during connection
	bodyBytes  []byte        // Cached body bytes for retry support
	request    *http.Request // The underlying standard HTTP request
	cli        *Client       // The associated surf client for this request
	multipart  *Multipart    // Multipart form data for file uploads and form submissions
}

// GetRequest returns the underlying standard http.Request.
// Provides access to the wrapped HTTP request for advanced use cases.
func (req *Request) GetRequest() *http.Request { return req.request }

// Multipart sets multipart form data for the request.
// The provided Multipart object contains form fields and files to be sent.
// Returns the request for method chaining. If m is nil, an error is set on the request.
func (req *Request) Multipart(m *Multipart) *Request {
	if req.err != nil {
		return req
	}

	if m == nil {
		req.err = fmt.Errorf("multipart is nil")
		return req
	}

	req.multipart = m
	return req
}

// prepareMultipart prepares the multipart body for the request.
// It sets up the request body with a pipe reader and configures the Content-Type header.
// Returns an error if both Body() and Multipart() were called, as they are mutually exclusive.
func (req *Request) prepareMultipart() {
	if req.multipart == nil {
		return
	}

	if req.request.Body != nil {
		req.err = fmt.Errorf("cannot use both Body() and Multipart() - they are mutually exclusive")
		return
	}

	pr, contentType := req.multipart.prepareWriter(req.cli.boundary)

	req.request.Body = pr
	req.request.Header.Set(header.CONTENT_TYPE, contentType)
}

// Do executes the HTTP request and returns a Response wrapped in a Result type.
// This is the main method that performs the actual HTTP request with full surf functionality:
// - Applies request middleware (authentication, headers, tracing, etc.)
// - Preserves request body for potential retries
// - Implements retry logic with configurable status codes and delays
// - Measures request timing for performance analysis
// - Handles request preparation errors and write errors
func (req *Request) Do() g.Result[*Response] {
	// Return early if request has preparation errors
	if req.err != nil {
		return g.Err[*Response](req.err)
	}

	req.prepareMultipart()
	if req.err != nil {
		return g.Err[*Response](req.err)
	}

	// Apply all configured request middleware
	if err := req.cli.applyReqMW(req); err != nil {
		return g.Err[*Response](err)
	}

	// Preserve request body for retries (except HEAD requests which have no body)
	if req.request.Method != http.MethodHead {
		req.bodyBytes, req.request.Body, req.err = drainbody.DrainBody(req.request.Body)
		if req.err != nil {
			return g.Err[*Response](req.err)
		}
	}

	var (
		resp     *http.Response
		attempts int
		err      error
	)

	start := time.Now()
	cli := req.cli.cli

	builder := req.cli.builder

	// Execute request with retry logic
retry:
	// Restore body from saved bytes for retry attempts
	if attempts > 0 && req.bodyBytes != nil {
		req.request.Body = io.NopCloser(bytes.NewReader(req.bodyBytes))
	}

	resp, err = cli.Do(req.request)
	if err != nil {
		return g.Err[*Response](err)
	}

	// Check if retry is needed based on status code and retry configuration
	if builder != nil && builder.retryMax != 0 && attempts < builder.retryMax && !builder.retryCodes.IsEmpty() &&
		builder.retryCodes.Contains(resp.StatusCode) {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		attempts++

		time.Sleep(builder.retryWait)
		goto retry
	}

	response := &Response{
		Attempts:      attempts,
		Time:          time.Since(start),
		Client:        req.cli,
		ContentLength: resp.ContentLength,
		Cookies:       resp.Cookies(),
		Headers:       Headers(resp.Header),
		Proto:         g.String(resp.Proto),
		StatusCode:    StatusCode(resp.StatusCode),
		URL:           resp.Request.URL,
		UserAgent:     g.String(req.request.UserAgent()),
		remoteAddr:    req.remoteAddr,
		request:       req,
		response:      resp,
	}

	if req.request.Method != http.MethodHead {
		response.Body = &Body{
			Reader:        resp.Body,
			cache:         builder != nil && builder.cacheBody,
			contentType:   resp.Header.Get(header.CONTENT_TYPE),
			contentLength: resp.ContentLength,
			limit:         -1,
			ctx:           req.request.Context(),
		}
	}

	if err := req.cli.applyRespMW(response); err != nil {
		return g.Err[*Response](err)
	}

	return g.Ok(response)
}

// WithContext associates a context with the request for cancellation and deadlines.
// The context can be used to cancel the request, set timeouts, or pass request-scoped values.
// Returns the request for method chaining. If ctx is nil, the request is unchanged.
func (req *Request) WithContext(ctx context.Context) *Request {
	if ctx != nil {
		req.request = req.request.WithContext(ctx)
	}

	return req
}

// AddCookies adds one or more HTTP cookies to the request.
// Cookies are added to the request headers and will be sent with the HTTP request.
// Returns the request for method chaining.
func (req *Request) AddCookies(cookies ...*http.Cookie) *Request {
	for _, cookie := range cookies {
		req.request.AddCookie(cookie)
	}

	return req
}

// SetHeaders sets HTTP headers for the request, replacing any existing headers with the same name.
// Supports multiple input formats:
// - Two arguments: key, value (string or g.String)
// - Single argument: http.Header, Headers, map types, or g.Map types
// Maintains header order for fingerprinting purposes when using g.MapOrd.
// Returns the request for method chaining.
func (req *Request) SetHeaders(headers ...any) *Request {
	if req.request == nil || headers == nil {
		return req
	}

	req.applyHeaders(headers, func(h http.Header, k, v string) { h.Set(k, v) })

	return req
}

// AddHeaders adds HTTP headers to the request, appending to any existing headers with the same name.
// Unlike SetHeaders, this method preserves existing headers and adds new values.
// Supports the same input formats as SetHeaders.
// Returns the request for method chaining.
func (req *Request) AddHeaders(headers ...any) *Request {
	if req.request == nil || headers == nil {
		return req
	}

	req.applyHeaders(headers, func(h http.Header, k, v string) { h.Add(k, v) })

	return req
}

// applyHeaders is a helper function that processes various header input formats and applies them to an HTTP request.
// It handles type checking, conversion, and delegation to the provided setOrAdd function for actual header manipulation.
// Supports ordered header maps for fingerprinting and maintains compatibility with multiple map and header types.
func (req *Request) applyHeaders(
	rawHeaders []any,
	setOrAdd func(h http.Header, key, value string),
) {
	r := req.request
	if len(rawHeaders) >= 2 {
		var key, value string

		switch k := rawHeaders[0].(type) {
		case string:
			key = k
		case g.String:
			key = k.Std()
		default:
			panic(fmt.Sprintf("unsupported key type: expected 'string' or 'String', got %T", rawHeaders[0]))
		}

		switch v := rawHeaders[1].(type) {
		case string:
			value = v
		case g.String:
			value = v.Std()
		default:
			panic(fmt.Sprintf("unsupported value type: expected 'string' or 'String', got %T", rawHeaders[1]))
		}

		setOrAdd(r.Header, key, value)
		return
	}

	switch h := rawHeaders[0].(type) {
	case http.Header:
		for key, values := range h {
			for _, value := range values {
				setOrAdd(r.Header, key, value)
			}
		}
	case Headers:
		for key, values := range h {
			for _, value := range values {
				setOrAdd(r.Header, key, value)
			}
		}
	case map[string]string:
		for key, value := range h {
			setOrAdd(r.Header, key, value)
		}
	case map[g.String]g.String:
		for key, value := range h {
			setOrAdd(r.Header, key.Std(), value.Std())
		}
	case g.Map[string, string]:
		for key, value := range h {
			setOrAdd(r.Header, key, value)
		}
	case g.Map[g.String, g.String]:
		for key, value := range h {
			setOrAdd(r.Header, key.Std(), value.Std())
		}
	case g.MapOrd[string, string]:
		updated := updateRequestHeaderOrder(req, h)
		updated.Iter().ForEach(func(key, value string) { setOrAdd(r.Header, key, value) })
	case g.MapOrd[g.String, g.String]:
		updated := updateRequestHeaderOrder(req, h)
		updated.Iter().ForEach(func(key, value g.String) { setOrAdd(r.Header, key.Std(), value.Std()) })
	default:
		panic(fmt.Sprintf("unsupported headers type: expected 'http.Header', 'surf.Headers', 'map[~string]~string', 'Map[~string, ~string]', or 'MapOrd[~string, ~string]', got %T", rawHeaders[0]))
	}
}

// updateRequestHeaderOrder processes ordered headers for HTTP/2 and HTTP/3 fingerprinting.
// It maintains the specific order of headers which is crucial for browser fingerprinting.
// Separates regular headers from pseudo-headers (starting with ':') and sets the appropriate
// header order keys for the transport layer to use. Returns a filtered map containing only
// non-pseudo headers with non-empty values.
func updateRequestHeaderOrder[T ~string](r *Request, h g.MapOrd[T, T]) g.MapOrd[T, T] {
	if r.cli.builder != nil {
		method := r.request.Method
		if r.cli.builder.http3 {
			method += "http3"
		}

		switch r.cli.builder.browser {
		case chromeBrowser:
			chrome.Headers(&h, method)
		case firefoxBrowser:
			firefox.Headers(&h, method)
		}
	}

	headersKeys := g.TransformSlice(h.Iter().
		Keys().
		Map(func(s T) T { return T(g.String(s).Lower()) }).
		Collect(), func(t T) string { return string(t) })

	headers, pheaders := headersKeys.Iter().Partition(func(v string) bool { return v[0] != ':' })

	if !headers.IsEmpty() {
		r.request.Header[http.HeaderOrderKey] = headers
	}

	if !pheaders.IsEmpty() {
		r.request.Header[http.PHeaderOrderKey] = pheaders
	}

	return h.Iter().
		Filter(func(header, data T) bool { return header[0] != ':' && len(data) != 0 }).
		Collect()
}
