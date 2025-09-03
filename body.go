package surf

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"regexp"

	"github.com/enetx/g"
	"github.com/enetx/surf/pkg/sse"
	"golang.org/x/net/html/charset"
)

// Body represents an HTTP response body with enhanced functionality and automatic caching.
// Provides convenient methods for parsing common data formats (JSON, XML, text) and includes
// features like automatic decompression, content caching, character set detection, and size limits.
type Body struct {
	Reader      io.ReadCloser // ReadCloser for accessing the raw body content
	contentType string        // MIME content type from Content-Type header
	content     g.Bytes       // Cached body content (populated when cache is enabled)
	limit       int64         // Maximum allowed body size in bytes (-1 for unlimited)
	cache       bool          // Whether to cache the body content in memory for reuse
}

// MD5 returns the MD5 hash of the body's content as a HString.
func (b *Body) MD5() g.String { return b.String().Hash().MD5() }

// XML decodes the body's content as XML into the provided data structure.
func (b *Body) XML(data any) error {
	return xml.Unmarshal(b.Bytes(), data)
}

// JSON decodes the body's content as JSON into the provided data structure.
func (b *Body) JSON(data any) error { return json.Unmarshal(b.Bytes(), data) }

// Stream returns the body's bufio.Reader for streaming the content.
func (b *Body) Stream() *bufio.Reader {
	if b == nil || b.Reader == nil {
		return nil
	}

	return bufio.NewReader(b.Reader)
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
		return errors.New("cannot close: body is empty or contains no content")
	}

	if _, err := io.Copy(io.Discard, b.Reader); err != nil {
		return err
	}

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

// Bytes returns the body's content as a byte slice.
func (b *Body) Bytes() g.Bytes {
	if b == nil {
		return nil
	}

	if b.cache && b.content != nil {
		return b.content
	}

	if _, err := b.Reader.Read(nil); err != nil {
		if err.Error() == "http: read on closed response body" {
			return nil
		}
	}

	defer b.Close()

	if b.limit == -1 {
		b.limit = math.MaxInt64
	}

	content, err := io.ReadAll(io.LimitReader(b.Reader, b.limit))
	if err != nil {
		return nil
	}

	if b.cache {
		b.content = content
	}

	return content
}

// Dump dumps the body's content to a file with the given filename.
func (b *Body) Dump(filename g.String) error {
	if b == nil || b.Reader == nil {
		return errors.New("cannot dump: body is empty or contains no content")
	}

	defer b.Close()

	return g.NewFile(filename).WriteFromReader(b.Reader).Err()
}

// Contains checks if the body's content contains the provided pattern (byte slice, string, or
// *regexp.Regexp) and returns a boolean.
func (b *Body) Contains(pattern any) bool {
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
