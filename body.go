package surf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf/pkg/sse"
	"golang.org/x/net/html/charset"
)

// Body represents an HTTP response body with enhanced functionality and automatic caching.
// Provides convenient methods for parsing common data formats (JSON, XML, text) and includes
// features like automatic decompression, content caching, character set detection, and size limits.
type Body struct {
	// Cached body content.
	// Populated only when cache == true and the body has been read.
	// Uses g.Result to store either the bytes or an error.
	content g.Result[g.Bytes]

	// MIME content type extracted from the Content-Type response header.
	// Used for charset detection and UTF-8 conversion.
	contentType string

	// Context associated with this body.
	// Used to support cancellation of read operations.
	ctx context.Context

	// Underlying body reader (usually http.Response.Body).
	// Provides access to the raw response stream.
	Reader io.ReadCloser

	// Ensures the body is read and cached exactly once when cache == true.
	// Prevents duplicate reads of the underlying stream.
	readOnce sync.Once

	// Ensures the underlying reader is closed exactly once.
	// Protects against multiple Close() calls.
	closeOnce sync.Once

	// Ensures context cancellation monitoring is set up only once.
	// Prevents spawning multiple goroutines for the same body.
	setupOnce sync.Once

	// Content length in bytes as reported by the Content-Length header.
	// A value of -1 means the length is unknown.
	contentLength int64

	// Maximum allowed body size in bytes.
	// A value of -1 means no limit (unbounded).
	limit int64

	// Enables in-memory caching of the body content.
	// When true, the body can be read multiple times via Bytes(), String(), JSON(), etc.
	cache bool

	// Channel used to signal cancellation of an ongoing read operation.
	// Closed when the body is closed or the context is done.
	cancelRead chan g.Unit

	// Indicates whether body reading has started.
	// Used to prevent context changes after read operations begin.
	readStarted atomic.Bool
}

// setupContextCancel initializes context cancellation monitoring.
func (b *Body) setupContextCancel() {
	b.setupOnce.Do(func() {
		b.readStarted.Store(true)

		if b.ctx == nil || b.Reader == nil {
			return
		}

		conn, ok := b.Reader.(interface{ SetReadDeadline(time.Time) error })
		if !ok {
			return
		}

		b.cancelRead = make(chan g.Unit)

		go func() {
			select {
			case <-b.ctx.Done():
				conn.SetReadDeadline(time.Now().Add(-time.Second))
			case <-b.cancelRead:
			}
		}()
	})
}

// checkContext returns context error if context is cancelled.
func (b *Body) checkContext() error {
	if b.ctx != nil {
		return b.ctx.Err()
	}

	return nil
}

// Bytes returns the body's content as a byte slice.
func (b *Body) Bytes() g.Result[g.Bytes] {
	if b == nil {
		return g.Err[g.Bytes](errors.New("body is nil"))
	}

	if b.cache {
		b.readOnce.Do(func() {
			b.content = b.read()
		})

		return b.content
	}

	return b.read()
}

// read reads the body content exactly once and returns it as g.Bytes.
// It closes the underlying reader when finished. If a context is provided,
// reading will be canceled if the context is done.
// The read is limited by b.limit (if -1, unlimited), and io.LimitReader ensures the size limit.
func (b *Body) read() g.Result[g.Bytes] {
	if b.Reader == nil {
		return g.Err[g.Bytes](errors.New("body reader is nil"))
	}

	defer b.Close()

	if err := b.checkContext(); err != nil {
		return g.Err[g.Bytes](err)
	}

	b.setupContextCancel()

	limit := b.limit
	if limit == -1 {
		limit = math.MaxInt64
	}

	buf := new(bytes.Buffer)
	if cl := b.contentLength; cl > 0 && cl <= limit && cl <= math.MaxInt32 {
		buf.Grow(int(cl))
	} else {
		buf.Grow(16384)
	}

	_, err := io.Copy(buf, io.LimitReader(b.Reader, limit))
	if err != nil {
		return g.Err[g.Bytes](err)
	}

	return g.Ok[g.Bytes](buf.Bytes())
}

// XML decodes the body's content as XML into the provided data structure.
func (b *Body) XML(data any) error {
	r := b.Bytes()
	if r.IsErr() {
		return r.Err()
	}

	return xml.Unmarshal(r.Ok(), data)
}

// JSON decodes the body's content as JSON into the provided data structure.
func (b *Body) JSON(data any) error {
	r := b.Bytes()
	if r.IsErr() {
		return r.Err()
	}

	return json.Unmarshal(r.Ok(), data)
}

// Stream returns a bufio.Reader for streaming the body content.
// IMPORTANT: Call this method once and reuse the returned reader.
// Each call creates a new bufio.Reader; calling repeatedly in a loop will lose buffered data.
func (b *Body) Stream() *StreamReader {
	if b == nil || b.Reader == nil {
		return nil
	}

	b.setupContextCancel()

	return &StreamReader{
		Reader: bufio.NewReader(b.Reader),
		body:   b,
	}
}

// StreamReader wraps bufio.Reader with Close support.
type StreamReader struct {
	*bufio.Reader
	body *Body
}

// Close closes the underlying body.
func (s *StreamReader) Close() error {
	if s.body != nil {
		return s.body.Close()
	}
	return nil
}

// SSE reads the body's content as Server-Sent Events (SSE) and calls the provided function for each event.
// It expects the function to take an *sse.Event pointer as its argument and return a boolean value.
// If the function returns false, the SSE reading stops.
func (b *Body) SSE(fn func(event *sse.Event) bool) error {
	stream := b.Stream()
	if stream == nil {
		return errors.New("sse: body is empty")
	}

	defer stream.Close()

	return sse.Read(stream.Reader, fn)
}

// String returns the body's content as a g.String.
func (b *Body) String() g.Result[g.String] {
	r := b.Bytes()
	if r.IsErr() {
		return g.Err[g.String](r.Err())
	}

	return g.Ok(r.Ok().String())
}

// Limit sets the body's size limit and returns the modified body.
func (b *Body) Limit(limit int64) *Body {
	if b != nil {
		b.limit = limit
	}

	return b
}

// WithContext sets the context for cancellation of read operations.
//
// Must be called BEFORE reading the body (Bytes(), String(), Stream(), etc.).
// Silently ignored if reading has already started.
func (b *Body) WithContext(ctx context.Context) *Body {
	if b == nil {
		return nil
	}

	if !b.readStarted.Load() {
		b.ctx = ctx
	}

	return b
}

// Close closes the body and returns any error encountered.
// It drains remaining data for connection reuse, but respects context cancellation.
func (b *Body) Close() error {
	if b == nil || b.Reader == nil {
		return nil
	}

	var err error

	b.closeOnce.Do(func() {
		if b.cancelRead != nil {
			close(b.cancelRead)
		}

		if b.ctx == nil || b.ctx.Err() == nil {
			io.CopyN(io.Discard, b.Reader, 256*1024)
		}

		err = b.Reader.Close()
	})

	return err
}

// UTF8 converts the body's content to UTF-8 encoding and returns it as a string.
func (b *Body) UTF8() g.Result[g.String] {
	if b == nil {
		return g.Err[g.String](errors.New("body is nil"))
	}

	r := b.Bytes()
	if r.IsErr() {
		return g.Err[g.String](r.Err())
	}

	reader, err := charset.NewReader(r.Ok().Reader(), b.contentType)
	if err != nil {
		return g.Err[g.String](err)
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return g.Err[g.String](err)
	}

	return g.Ok(g.String(content))
}

// Dump dumps the body's content to a file with the given filename.
func (b *Body) Dump(filename g.String) error {
	if b == nil || b.Reader == nil {
		return errors.New("body reader is nil")
	}

	if b.cache {
		content := b.Bytes()
		if content.IsErr() {
			return content.Err()
		}

		return g.NewFile(filename).Write(content.Ok().String()).Err()
	}

	defer b.Close()

	b.setupContextCancel()

	return g.NewFile(filename).WriteFromReader(b.Reader).Err()
}

// Contains checks if the body's content contains the provided pattern (byte slice, string, or
// *regexp.Regexp) and returns a boolean.
func (b *Body) Contains(pattern any) bool {
	if b == nil {
		return false
	}

	r := b.Bytes()
	if r.IsErr() {
		return false
	}

	switch p := pattern.(type) {
	case []byte:
		return r.Ok().Lower().Contains(g.Bytes(p).Lower())
	case g.Bytes:
		return r.Ok().Lower().Contains(p.Lower())
	case string:
		return r.Ok().String().Lower().Contains(g.String(p).Lower())
	case g.String:
		return r.Ok().String().Lower().Contains(p.Lower())
	case *regexp.Regexp:
		return r.Ok().String().Regexp().Match(p)
	}

	return false
}
