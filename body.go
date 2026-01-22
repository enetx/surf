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

	"github.com/enetx/g"
	"github.com/enetx/surf/pkg/sse"
	"golang.org/x/net/html/charset"
)

// reader is a wrapper around an io.Reader that supports cancellation via context.Context.
// It allows blocking read operations to be interrupted if the context is canceled or times out.
type reader struct {
	r   io.Reader       // The underlying data source
	ctx context.Context // Context used for canceling the read
}

// Read reads data from the internal io.Reader into the provided buffer p.
// If the context ctx is canceled, Read immediately returns ctx.Err().
// Otherwise, it behaves like a normal io.Reader, returning the number of bytes read
// and any read error encountered.
func (c *reader) Read(p []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
		return c.r.Read(p)
	}
}

// Body represents an HTTP response body with enhanced functionality and automatic caching.
// Provides convenient methods for parsing common data formats (JSON, XML, text) and includes
// features like automatic decompression, content caching, character set detection, and size limits.
type Body struct {
	content       g.Bytes         // Cached body content (populated when cache is enabled)
	contentType   string          // MIME content type from Content-Type header
	ctx           context.Context // Context associated with this Body
	Reader        io.ReadCloser   // ReadCloser for accessing the raw body content
	once          sync.Once       // Ensures the body is read and cached exactly once
	contentLength int64           // Content length in bytes from Content-Length header (-1 if unknown)
	limit         int64           // Maximum allowed body size in bytes (-1 for unlimited)
	cache         bool            // Whether to cache the body content in memory for reuse
}

// Bytes returns the body's content as a byte slice.
func (b *Body) Bytes() g.Bytes {
	if b == nil {
		return g.Bytes{}
	}

	if b.cache {
		b.once.Do(func() { b.content = b.read() })
		return b.content
	}

	return b.read()
}

// read reads the body content exactly once and returns it as g.Bytes.
// It closes the underlying reader when finished. If a context is provided,
// reading will be canceled if the context is done.
// The read is limited by b.limit (if -1, unlimited), and io.LimitReader ensures the size limit.
func (b *Body) read() g.Bytes {
	if b.Reader == nil {
		return g.Bytes{}
	}

	defer b.Close()

	var r io.Reader = b.Reader
	if b.ctx != nil {
		r = &reader{ctx: b.ctx, r: b.Reader}
	}

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

	io.Copy(buf, io.LimitReader(r, limit))
	return buf.Bytes()
}

// MD5 returns the MD5 hash of the body's content as a g.String.
func (b *Body) MD5() g.String { return b.String().Hash().MD5() }

// XML decodes the body's content as XML into the provided data structure.
func (b *Body) XML(data any) error { return xml.Unmarshal(b.Bytes(), data) }

// JSON decodes the body's content as JSON into the provided data structure.
func (b *Body) JSON(data any) error { return json.Unmarshal(b.Bytes(), data) }

// Stream returns a bufio.Reader for streaming the body content.
// IMPORTANT: Call this method once and reuse the returned reader.
// Each call creates a new bufio.Reader; calling repeatedly in a loop will lose buffered data.
func (b *Body) Stream() *bufio.Reader {
	if b == nil || b.Reader == nil {
		return nil
	}

	var r io.Reader = b.Reader
	if b.ctx != nil {
		r = &reader{ctx: b.ctx, r: b.Reader}
	}

	return bufio.NewReader(r)
}

// SSE reads the body's content as Server-Sent Events (SSE) and calls the provided function for each event.
// It expects the function to take an *sse.Event pointer as its argument and return a boolean value.
// If the function returns false, the SSE reading stops.
func (b *Body) SSE(fn func(event *sse.Event) bool) error { return sse.Read(b.Stream(), fn) }

// String returns the body's content as a g.String.
func (b *Body) String() g.String { return b.Bytes().String() }

// Limit sets the body's size limit and returns the modified body.
func (b *Body) Limit(limit int64) *Body {
	if b != nil {
		b.limit = limit
	}

	return b
}

// Close closes the body and returns any error encountered.
func (b *Body) Close() error {
	if b == nil || b.Reader == nil {
		return nil
	}

	io.Copy(io.Discard, b.Reader)
	return b.Reader.Close()
}

// UTF8 converts the body's content to UTF-8 encoding and returns it as a string.
func (b *Body) UTF8() g.String {
	if b == nil {
		return ""
	}

	reader, err := charset.NewReader(b.Bytes().Reader(), b.contentType)
	if err != nil {
		return b.String()
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return b.String()
	}

	return g.String(content)
}

// Dump dumps the body's content to a file with the given filename.
func (b *Body) Dump(filename g.String) error {
	if b == nil || b.Reader == nil {
		return errors.New("cannot dump: body is empty or contains no content")
	}

	if b.cache && b.content != nil {
		return g.NewFile(filename).Write(b.content.String()).Err()
	}

	defer b.Close()

	return g.NewFile(filename).WriteFromReader(b.Reader).Err()
}

// Contains checks if the body's content contains the provided pattern (byte slice, string, or
// *regexp.Regexp) and returns a boolean.
func (b *Body) Contains(pattern any) bool {
	if b == nil {
		return false
	}

	switch p := pattern.(type) {
	case []byte:
		return b.Bytes().Lower().Contains(g.Bytes(p).Lower())
	case g.Bytes:
		return b.Bytes().Lower().Contains(p.Lower())
	case string:
		return b.String().Lower().Contains(g.String(p).Lower())
	case g.String:
		return b.String().Lower().Contains(p.Lower())
	case *regexp.Regexp:
		return b.String().Regexp().Match(p)
	}

	return false
}
