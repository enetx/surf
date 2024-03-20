package surf

import (
	"bufio"
	"errors"
	"io"
	"math"
	"regexp"

	"github.com/enetx/g"
	"golang.org/x/net/html/charset"
)

// body represents the content and properties of an HTTP response body.
type body struct {
	Reader      io.ReadCloser // ReadCloser for accessing the body content.
	contentType string        // Content type of the body.
	content     g.Bytes       // Content of the body as Bytes.
	limit       int64         // Maximum allowed size of the body.
	cache       bool          // Indicates if the body is cacheable.
}

// MD5 returns the MD5 hash of the body's content as a HString.
func (b *body) MD5() g.String { return b.String().Hash().MD5() }

// XML decodes the body's content as XML into the provided data structure.
func (b *body) XML(data any) error { return b.String().Dec().XML(data).Err() }

// JSON decodes the body's content as JSON into the provided data structure.
func (b *body) JSON(data any) error { return b.String().Dec().JSON(data).Err() }

// Stream returns the body's bufio.Reader for streaming the content.
func (b *body) Stream() *bufio.Reader {
	if b == nil || b.Reader == nil {
		return nil
	}

	return bufio.NewReader(b.Reader)
}

// String returns the body's content as a g.String.
func (b *body) String() g.String { return b.Bytes().ToString() }

// Limit sets the body's size limit and returns the modified body.
func (b *body) Limit(limit int64) *body {
	if b != nil {
		b.limit = limit
	}

	return b
}

// Close closes the body and returns any error encountered.
func (b *body) Close() error {
	if b == nil || b.Reader == nil {
		return errors.New("cannot close: body is empty or contains no content")
	}

	if _, err := io.Copy(io.Discard, b.Reader); err != nil {
		return err
	}

	return b.Reader.Close()
}

// UTF8 converts the body's content to UTF-8 encoding and returns it as a string.
func (b *body) UTF8() g.String {
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
func (b *body) Bytes() g.Bytes {
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
func (b *body) Dump(filename string) error {
	if b == nil || b.Reader == nil {
		return errors.New("cannot dump: body is empty or contains no content")
	}

	defer b.Close()

	return g.NewFile(g.String(filename)).WriteFromReader(b.Reader).Err()
}

// Contains checks if the body's content contains the provided pattern (byte slice, string, or
// *regexp.Regexp) and returns a boolean.
func (b *body) Contains(pattern any) bool {
	switch p := pattern.(type) {
	case []byte:
		return b.Bytes().Lower().Contains(g.Bytes(p).Lower())
	case string:
		return b.String().Lower().Contains(g.String(p).Lower())
	case *regexp.Regexp:
		return b.String().ContainsRegexp(g.String(p.String())).Ok()
	}

	return false
}
