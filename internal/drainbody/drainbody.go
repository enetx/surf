package drainbody

import (
	"bytes"
	"io"

	"github.com/enetx/http"
)

// drainBody reads all of b to memory and then returns two equivalent
// ReadClosers yielding the same bytes.
// It returns an error if the initial slurp of all bytes fails. It does not attempt
// to make the returned ReadClosers have identical error-matching behavior.
func DrainBody(b io.ReadCloser) (io.ReadCloser, io.ReadCloser, error) {
	if b == nil || b == http.NoBody {
		return nil, nil, nil
	}

	var buf bytes.Buffer

	if _, err := buf.ReadFrom(b); err != nil {
		return nil, nil, err
	}

	if err := b.Close(); err != nil {
		return nil, nil, err
	}

	return io.NopCloser(&buf), io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}
