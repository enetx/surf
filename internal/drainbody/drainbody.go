package drainbody

import (
	"bytes"
	"io"

	"github.com/enetx/http"
)

// DrainBody reads all of b to memory and returns the bytes and a new ReadCloser.
// It returns an error if the initial slurp of all bytes fails.
// The returned bytes can be reused for retry support.
func DrainBody(b io.ReadCloser) ([]byte, io.ReadCloser, error) {
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

	data := buf.Bytes()

	return data, io.NopCloser(bytes.NewReader(data)), nil
}
