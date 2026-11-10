package surf

import (
	"fmt"
	"io"
	"sync"

	"github.com/enetx/http"
)

// StreamingBody sends body without reading it into memory first. An optional
// length declares its size; omitted or -1 means unknown, and zero means empty.
// Surf owns and closes body. Blocking readers must implement Close so it
// unblocks Read, as required by http.Request.Body. This body is sent once:
// status retries, 307/308 redirects and protocol fallback need a replay factory.
func (req *Request) StreamingBody(body io.Reader, length ...int64) *Request {
	if req.err != nil {
		return req
	}

	size, err := streamingBodyLength(length)
	if err != nil {
		req.err = err
		return req
	}

	if body == nil {
		req.err = fmt.Errorf("streaming body is nil")
		return req
	}

	if err := req.resetStreamingBody(); err != nil {
		req.err = err
		return req
	}

	closer, ok := body.(io.ReadCloser)
	if !ok {
		closer = io.NopCloser(body)
	}

	req.streamingBody = true
	req.bodyBytes = nil
	req.request.GetBody = nil
	req.request.ContentLength = size
	req.request.Body = &streamingRequestBody{ReadCloser: closer}

	if size == 0 {
		req.err = req.request.Body.Close()
		req.request.Body = http.NoBody
	}

	return req
}

// StreamingBodyFactory creates a fresh streaming body for the initial attempt,
// retries, redirects and protocol fallback. No body is buffered. The factory is
// called when sending, must return a new non-nil reader on each call, and must
// be concurrency safe. Length follows StreamingBody; a zero-length body does
// not call the factory. Surf owns every reader returned by the factory.
func (req *Request) StreamingBodyFactory(factory func() (io.ReadCloser, error), length ...int64) *Request {
	if req.err != nil {
		return req
	}

	size, err := streamingBodyLength(length)
	if err != nil {
		req.err = err
		return req
	}

	if factory == nil {
		req.err = fmt.Errorf("streaming body factory is nil")
		return req
	}

	if err := req.resetStreamingBody(); err != nil {
		req.err = err
		return req
	}

	req.streamingBody = true
	req.streamingFactory = true
	req.bodyBytes = nil
	req.request.ContentLength = size
	req.request.Body = nil
	req.request.GetBody = func() (io.ReadCloser, error) {
		body, err := factory()
		if err != nil {
			if body != nil {
				body.Close()
			}

			return nil, err
		}

		if body == nil {
			return nil, fmt.Errorf("streaming body factory returned nil")
		}

		return &streamingRequestBody{ReadCloser: body}, nil
	}

	if size == 0 {
		req.request.Body = http.NoBody
		req.request.GetBody = nil
	}

	return req
}

func streamingBodyLength(length []int64) (int64, error) {
	if len(length) > 1 {
		return 0, fmt.Errorf("streaming body accepts at most one length")
	}

	if len(length) == 0 {
		return -1, nil
	}

	if length[0] < -1 {
		return 0, fmt.Errorf("streaming body length must be -1 or nonnegative")
	}

	return length[0], nil
}

func (req *Request) resetStreamingBody() error {
	if err := req.closeStreamingBody(); err != nil {
		return err
	}

	req.streamingBody = false
	req.streamingFactory = false
	req.bodyBytes = nil
	req.request.GetBody = nil

	return nil
}

func (req *Request) closeStreamingBody() error {
	if req.streamingBody && req.request != nil && req.request.Body != nil {
		return req.request.Body.Close()
	}

	return nil
}

func (req *Request) prepareStreamingBody() error {
	if !req.streamingBody {
		return nil
	}

	if err := req.request.Context().Err(); err != nil {
		return err
	}

	if req.streamingFactory && req.request.GetBody != nil {
		if req.request.Body != nil {
			req.request.Body.Close()
		}

		body, err := req.request.GetBody()
		if err != nil {
			return err
		}

		req.request.Body = body
	}

	return nil
}

func (req *Request) canReplayStreamingBody() bool {
	return !req.streamingBody || req.request.Body == nil || req.request.Body == http.NoBody ||
		req.request.GetBody != nil
}

type streamingRequestBody struct {
	io.ReadCloser
	once     sync.Once
	closeErr error
}

func (body *streamingRequestBody) Close() error {
	body.once.Do(func() { body.closeErr = body.ReadCloser.Close() })
	return body.closeErr
}
