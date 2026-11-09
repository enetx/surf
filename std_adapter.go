package surf

import (
	_http "net/http"
	"net/url"

	"github.com/enetx/http"
	"github.com/enetx/surf/header"
)

// Std returns a standard net/http.Client that wraps the configured surf client.
// This is useful for integrating with third-party libraries that expect a standard net/http.Client
// while preserving most surf features.
//
// Supported features:
//   - JA3/TLS fingerprinting
//   - HTTP/2 settings
//   - Cookies and sessions
//   - Request/Response middleware
//   - Headers (User-Agent, custom headers)
//   - Proxy configuration
//   - Timeout settings
//   - Redirect policies
//   - Impersonate browser headers
//
// Known limitations:
//   - Retry logic is NOT supported (implemented in Request.Do(), not in transport)
//   - Response body caching is NOT supported
//   - Remote address tracking is NOT supported
//   - Request timing information is NOT available
//
// For applications requiring retry logic, consider implementing it at the application level
// or use surf.Client directly for those specific requests.
//
// Example usage:
//
//	surfClient := surf.NewClient().
//		Builder().
//		JA3().Chrome().
//		Session().
//		Build()
//
//	// For libraries expecting net/http.Client
//	stdClient := surfClient.Std()
//
//	botClient := &BaseBotClient{
//		Client: *stdClient,
//	}
func (c *Client) Std() *_http.Client {
	var jar _http.CookieJar
	if c.cli.Jar != nil {
		jar = &CookieJarAdapter{jar: c.cli.Jar}
	}

	return &_http.Client{
		Transport: &TransportAdapter{
			transport: c.transport,
			client:    c,
		},
		Jar:           jar,
		Timeout:       c.cli.Timeout,
		CheckRedirect: redirect(c.cli.CheckRedirect),
	}
}

// TransportAdapter adapts surf.Client to net/http.RoundTripper
// It uses the full surf pipeline including middleware
type TransportAdapter struct {
	transport http.RoundTripper
	client    *Client
}

func (s *TransportAdapter) CloseIdleConnections() {
	if closer, ok := s.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// RoundTrip implements net/http.RoundTripper interface using surf's full pipeline
func (s *TransportAdapter) RoundTrip(req *_http.Request) (*_http.Response, error) {
	sreq := &Request{
		request: request(req),
		cli:     s.client,
	}

	if err := s.client.applyReqMW(sreq); err != nil {
		return nil, err
	}

	_resp, err := s.client.cli.Transport.RoundTrip(sreq.request)
	if err != nil {
		return nil, err
	}

	resp := &Response{
		response:   _resp,
		Client:     s.client,
		StatusCode: StatusCode(_resp.StatusCode),
		Headers:    Headers(_resp.Header),
		request:    sreq,
	}

	if _resp.Body != nil {
		resp.Body = &Body{
			Reader:        _resp.Body,
			contentType:   _resp.Header.Get(header.CONTENT_TYPE),
			contentLength: _resp.ContentLength,
			limit:         -1,
			ctx:           req.Context(),
		}
	}

	if err := s.client.applyRespMW(resp); err != nil {
		return nil, err
	}

	if resp.Body != nil {
		_resp.Body = resp.Body.Reader
	}

	return response(resp.response, req), nil
}

// request converts net/http.Request to github.com/enetx/http.Request.
// It preserves all fields including headers, body, and context while
// adapting to the enetx/http package types.
func request(_req *_http.Request) *http.Request {
	req := &http.Request{
		Method:           _req.Method,
		URL:              _req.URL,
		Proto:            _req.Proto,
		ProtoMajor:       _req.ProtoMajor,
		ProtoMinor:       _req.ProtoMinor,
		Header:           http.Header(_req.Header),
		Body:             _req.Body,
		ContentLength:    _req.ContentLength,
		TransferEncoding: _req.TransferEncoding,
		Close:            _req.Close,
		Host:             _req.Host,
		Form:             _req.Form,
		PostForm:         _req.PostForm,
		MultipartForm:    _req.MultipartForm,
		Trailer:          http.Header(_req.Trailer),
		RemoteAddr:       _req.RemoteAddr,
		RequestURI:       _req.RequestURI,
		TLS:              _req.TLS,
		Response:         nil,
		GetBody:          _req.GetBody,
		Pattern:          _req.Pattern,
		Cancel:           _req.Cancel, // deprecated but kept for compatibility
	}

	return req.WithContext(_req.Context())
}

// response converts github.com/enetx/http.Response to net/http.Response.
// It preserves all response fields including status, headers, and body
// while adapting back to standard net/http types.
func response(resp *http.Response, _req *_http.Request) *_http.Response {
	return &_http.Response{
		Status:           resp.Status,
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           _http.Header(resp.Header),
		Body:             resp.Body,
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          _http.Header(resp.Trailer),
		Request:          _req,
		TLS:              resp.TLS,
	}
}

// CookieJarAdapter adapts github.com/enetx/http.CookieJar to net/http.CookieJar.
// It provides bidirectional cookie conversion between the two HTTP packages,
// ensuring cookies set through either interface work correctly.
type CookieJarAdapter struct{ jar http.CookieJar }

// SetCookies implements http.CookieJar interface.
// It converts standard net/http cookies to enetx/http format and
// delegates to the underlying surf cookie jar.
func (c *CookieJarAdapter) SetCookies(u *url.URL, _cookies []*_http.Cookie) {
	if len(_cookies) == 0 {
		c.jar.SetCookies(u, nil)
		return
	}

	cookies := make([]*http.Cookie, 0, len(_cookies))
	for _, ck := range _cookies {
		cookies = append(cookies, &http.Cookie{
			Name:        ck.Name,
			Value:       ck.Value,
			Quoted:      ck.Quoted,
			Path:        ck.Path,
			Domain:      ck.Domain,
			Expires:     ck.Expires,
			RawExpires:  ck.RawExpires,
			MaxAge:      ck.MaxAge,
			Secure:      ck.Secure,
			HttpOnly:    ck.HttpOnly,
			SameSite:    http.SameSite(ck.SameSite),
			Partitioned: ck.Partitioned,
			Raw:         ck.Raw,
			Unparsed:    ck.Unparsed,
		})
	}

	c.jar.SetCookies(u, cookies)
}

// Cookies implements http.CookieJar interface.
// It retrieves cookies from the underlying surf cookie jar and
// converts them to standard net/http cookie format.
func (c *CookieJarAdapter) Cookies(u *url.URL) []*_http.Cookie {
	cookies := c.jar.Cookies(u)
	if len(cookies) == 0 {
		return nil
	}

	_cookies := make([]*_http.Cookie, 0, len(cookies))

	for _, ck := range cookies {
		_cookies = append(_cookies, &_http.Cookie{
			Name:        ck.Name,
			Value:       ck.Value,
			Quoted:      ck.Quoted,
			Path:        ck.Path,
			Domain:      ck.Domain,
			Expires:     ck.Expires,
			RawExpires:  ck.RawExpires,
			MaxAge:      ck.MaxAge,
			Secure:      ck.Secure,
			HttpOnly:    ck.HttpOnly,
			SameSite:    _http.SameSite(ck.SameSite),
			Partitioned: ck.Partitioned,
			Raw:         ck.Raw,
			Unparsed:    ck.Unparsed,
		})
	}

	return _cookies
}

// redirect adapts surf's redirect policy function to work with standard net/http.
// It converts net/http requests to enetx/http format, calls the surf redirect policy,
// and returns the result. This ensures custom redirect policies work correctly
// through the standard http.Client interface.
func redirect(fn func(*http.Request, []*http.Request) error) func(*_http.Request, []*_http.Request) error {
	if fn == nil {
		return nil
	}

	return func(req *_http.Request, via []*_http.Request) error {
		_req := request(req)
		_via := make([]*http.Request, len(via))
		for i := range via {
			_via[i] = request(via[i])
		}
		return fn(_req, _via)
	}
}
