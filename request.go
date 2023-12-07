package surf

import (
	"context"
	"io"
	"net"
	"strings"
	"time"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/surf/internal/drainbody"
)

// Request is a struct that holds information about an HTTP request.
type Request struct {
	request     *http.Request   // The underlying http.Request.
	client      *Client         // The associated client for the request.
	writeErr    *error          // An error encountered during writing.
	error       error           // A general error associated with the request.
	remoteAddr  net.Addr        // Remote network address.
	body        io.ReadCloser   // Request body.
	headersKeys g.Slice[string] // Order headers.
}

// GetRequest returns the underlying http.Request of the custom request.
func (req *Request) GetRequest() *http.Request { return req.request }

// Do performs the HTTP request and returns a Response object or an error if the request failed.
func (req *Request) Do() (*Response, error) {
	if req.error != nil {
		return nil, req.error
	}

	if err := req.client.applyReqMW(req); err != nil {
		return nil, err
	}

	opt := req.client.opt
	if opt != nil {
		if err := opt.applyReqMW(req); err != nil {
			return nil, err
		}
	}

	req.body, req.request.Body, req.error = drainbody.DrainBody(req.request.Body)
	if req.error != nil {
		return nil, req.error
	}

	var (
		resp     *http.Response
		attempts int
		err      error
	)

	start := time.Now()
	cli := req.client.cli

	for {
		resp, err = cli.Do(req.request)

		if err != nil || opt == nil || opt.retryMax == 0 || attempts >= opt.retryMax ||
			opt.retryCodes.Empty() || !opt.retryCodes.Contains(resp.StatusCode) {
			break
		}

		attempts++

		time.Sleep(opt.retryWait)
	}

	if err != nil {
		return nil, err
	}

	if req.writeErr != nil && (*req.writeErr).Error() != "" {
		return nil, *req.writeErr
	}

	response := &Response{
		Attempts:      attempts,
		Time:          time.Since(start),
		Client:        req.client,
		ContentLength: resp.ContentLength,
		Cookies:       resp.Cookies(),
		Headers:       headers(resp.Header),
		History:       req.client.history,
		Proto:         resp.Proto,
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		URL:           resp.Request.URL,
		UserAgent:     req.request.UserAgent(),
		remoteAddr:    req.remoteAddr,
		request:       req,
		response:      resp,
		Body: &body{
			body:        resp.Body,
			cache:       opt != nil && opt.cacheBody,
			contentType: resp.Header.Get("Content-Type"),
			deflate:     resp.Header.Get("Content-Encoding") == "deflate",
			gzip:        resp.Header.Get("Content-Encoding") == "gzip",
			brotli:      resp.Header.Get("Content-Encoding") == "br",
			limit:       -1,
		},
	}

	if err := req.client.applyRespMW(response); err != nil {
		return nil, err
	}

	if opt != nil {
		if err := opt.applyRespMW(response); err != nil {
			return nil, err
		}
	}

	return response, nil
}

// WithContext associates the provided context with the request.
func (req *Request) WithContext(ctx context.Context) *Request {
	if ctx != nil {
		req.request = req.request.WithContext(ctx)
	}

	return req
}

// AddCookies adds cookies to the request.
func (req *Request) AddCookies(cookies ...*http.Cookie) *Request {
	for _, cookie := range cookies {
		req.request.AddCookie(cookie)
	}

	return req
}

// SetHeaders sets headers for the request, replacing existing ones with the same name.
func (req *Request) SetHeaders(headers any) *Request {
	if headers == nil || req.request == nil {
		return req
	}

	switch h := any(headers).(type) {
	case map[string]string:
		for header, data := range h {
			req.request.Header.Set(header, data)
		}
	case *g.MapOrd[string, string]:
		h = req.orderHeaders(h)
		h.ForEach(func(header, data string) { req.request.Header.Set(header, data) })

	default:
		panic("use map[string]string or *g.MapOrd[string, string] for ordered headers")
	}

	return req
}

// AddHeaders adds headers to the request, appending to any existing headers with the same name.
func (req *Request) AddHeaders(headers any) *Request {
	if headers == nil || req.request == nil {
		return req
	}

	switch h := any(headers).(type) {
	case map[string]string:
		for header, data := range h {
			req.request.Header.Add(header, data)
		}
	case *g.MapOrd[string, string]:
		h = req.orderHeaders(h)
		h.ForEach(func(header, data string) { req.request.Header.Add(header, data) })
	default:
		panic("use map[string]string or *g.MapOrd[string, string] for ordered headers")
	}

	return req
}

func (req *Request) orderHeaders(h *g.MapOrd[string, string]) *g.MapOrd[string, string] {
	fh := func(h string) bool { return []rune(h)[0] != ':' }
	fph := func(h string) bool { return !fh(h) }

	req.headersKeys.AddUniqueInPlace(h.Keys().Map(strings.ToLower)...)

	if ho := req.headersKeys.Filter(fh); !ho.Empty() {
		req.request.Header[http.HeaderOrderKey] = ho
	}

	if pho := req.headersKeys.Filter(fph); !pho.Empty() {
		req.request.Header[http.PHeaderOrderKey] = pho
	}

	return h.Filter(func(header, data string) bool { return fh(header) && len(data) != 0 })
}
