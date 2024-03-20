package surf

import (
	"context"
	"io"
	"net"
	"strings"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/internal/drainbody"
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

	if req.request.Method != http.MethodHead {
		req.body, req.request.Body, req.error = drainbody.DrainBody(req.request.Body)
		if req.error != nil {
			return nil, req.error
		}
	}

	var (
		resp     *http.Response
		attempts int
		err      error
	)

	start := time.Now()
	cli := req.client.cli

retry:
	resp, err = cli.Do(req.request)
	if err != nil {
		return nil, err
	}

	if opt != nil && opt.retryMax != 0 && attempts < opt.retryMax && opt.retryCodes.NotEmpty() &&
		opt.retryCodes.Contains(resp.StatusCode) {
		attempts++

		time.Sleep(opt.retryWait)
		goto retry
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
		Proto:         resp.Proto,
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		URL:           resp.Request.URL,
		UserAgent:     req.request.UserAgent(),
		remoteAddr:    req.remoteAddr,
		request:       req,
		response:      resp,
	}

	if req.request.Method != http.MethodHead {
		response.Body = &body{
			Reader:      resp.Body,
			cache:       opt != nil && opt.cacheBody,
			contentType: resp.Header.Get(header.CONTENT_TYPE),
			limit:       -1,
		}
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
	case http.Header:
		for header, data := range h {
			req.request.Header.Set(header, data[0])
		}
	case map[string]string:
		for header, data := range h {
			req.request.Header.Set(header, data)
		}
	case g.MapOrd[string, string]:
		h = req.orderHeaders(h)
		h.Iter().ForEach(func(header, data string) { req.request.Header.Set(header, data) })
	default:
		panic("use http.Header, map[string]string or g.MapOrd[string, string] for ordered headers")
	}

	return req
}

// AddHeaders adds headers to the request, appending to any existing headers with the same name.
func (req *Request) AddHeaders(headers any) *Request {
	if headers == nil || req.request == nil {
		return req
	}

	switch h := any(headers).(type) {
	case http.Header:
		for header, data := range h {
			req.request.Header.Add(header, data[0])
		}
	case map[string]string:
		for header, data := range h {
			req.request.Header.Add(header, data)
		}
	case g.MapOrd[string, string]:
		h = req.orderHeaders(h)
		h.Iter().ForEach(func(header, data string) { req.request.Header.Add(header, data) })
	default:
		panic("use http.Header, map[string]string or g.MapOrd[string, string] for ordered headers")
	}

	return req
}

func (req *Request) orderHeaders(h g.MapOrd[string, string]) g.MapOrd[string, string] {
	req.headersKeys.AddUniqueInPlace(h.Iter().Keys().Map(strings.ToLower).Collect()...)

	fn := func(header string) bool { return header[0] != ':' }

	headers, pheaders := req.headersKeys.Iter().Partition(fn)

	if headers.NotEmpty() {
		req.request.Header[http.HeaderOrderKey] = headers
	}

	if pheaders.NotEmpty() {
		req.request.Header[http.PHeaderOrderKey] = pheaders
	}

	return h.Iter().Filter(func(header, data string) bool { return fn(header) && len(data) != 0 }).Collect()
}
