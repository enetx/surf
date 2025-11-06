package surf

import (
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
	request    *http.Request // The underlying standard HTTP request
	cli        *Client       // The associated surf client for this request
	werr       *error        // Pointer to error encountered during request writing/preparation
	err        error         // General error associated with the request (validation, setup, etc.)
	remoteAddr net.Addr      // Remote server address captured during connection
	body       io.ReadCloser // Request body reader (for retry support and body preservation)
}

// GetRequest returns the underlying standard http.Request.
// Provides access to the wrapped HTTP request for advanced use cases.
func (req *Request) GetRequest() *http.Request { return req.request }

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

	// Apply all configured request middleware
	if err := req.cli.applyReqMW(req); err != nil {
		return g.Err[*Response](err)
	}

	// Preserve request body for retries (except HEAD requests which have no body)
	if req.request.Method != http.MethodHead {
		req.body, req.request.Body, req.err = drainbody.DrainBody(req.request.Body)
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
	resp, err = cli.Do(req.request)
	if err != nil {
		return g.Err[*Response](err)
	}

	// Check if retry is needed based on status code and retry configuration
	if builder != nil && builder.retryMax != 0 && attempts < builder.retryMax && builder.retryCodes.NotEmpty() &&
		builder.retryCodes.Contains(resp.StatusCode) {
		attempts++

		time.Sleep(builder.retryWait)
		goto retry
	}

	// Check for write errors that occurred during request preparation
	if req.werr != nil && *req.werr != nil {
		return g.Err[*Response](*req.werr)
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
		response.Body = new(Body)
		response.Body.Reader = resp.Body
		response.Body.cache = builder != nil && builder.cacheBody
		response.Body.contentType = resp.Header.Get(header.CONTENT_TYPE)
		response.Body.limit = -1
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
	hclone := h.Clone()

	if r.cli.builder != nil {
		switch r.cli.builder.browser {
		case chromeBrowser:
			chrome.Headers(&hclone, r.request.Method)
		case firefoxBrowser:
			firefox.Headers(&hclone, r.request.Method)
		case chromeBrowserUB:
			chrome.HeadersUB(&hclone, r.request.Method)
		case firefoxBrowserUB:
			firefox.HeadersUB(&hclone, r.request.Method)
		}
	}

	headersKeys := g.TransformSlice(hclone.Iter().
		Keys().
		Map(func(s T) T { return T(g.String(s).Lower()) }).
		Collect(), func(t T) string { return string(t) })

	headers, pheaders := headersKeys.Iter().Partition(func(v string) bool { return v[0] != ':' })

	if headers.NotEmpty() {
		r.request.Header[http.HeaderOrderKey] = headers
	}

	if pheaders.NotEmpty() {
		r.request.Header[http.PHeaderOrderKey] = pheaders
	}

	return hclone.Iter().
		Filter(func(header, data T) bool { return header[0] != ':' && len(data) != 0 }).
		Collect()
}
