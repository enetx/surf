package surf

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/enetx/surf/header"
	"github.com/klauspost/compress/zstd"
)

type sourceCloseProbe struct {
	io.Reader
	closed bool
}

func (probe *sourceCloseProbe) Close() error {
	probe.closed = true
	return nil
}

func compressedPayload(t *testing.T, encoding string, payload []byte) []byte {
	t.Helper()

	var output bytes.Buffer
	var writer io.WriteCloser
	switch encoding {
	case "deflate":
		writer = zlib.NewWriter(&output)
	case "gzip":
		writer = gzip.NewWriter(&output)
	case "br":
		writer = brotli.NewWriter(&output)
	case "zstd":
		encoder, err := zstd.NewWriter(&output)
		if err != nil {
			t.Fatal(err)
		}
		writer = encoder
	default:
		t.Fatalf("unsupported test encoding %q", encoding)
	}

	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestDecodeBodyMiddlewareClosesCompressedSource(t *testing.T) {
	const payload = "response body"

	for _, encoding := range []string{"deflate", "gzip", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			source := &sourceCloseProbe{
				Reader: bytes.NewReader(compressedPayload(t, encoding, []byte(payload))),
			}
			headers := make(http.Header)
			headers.Set(header.CONTENT_ENCODING, encoding)
			response := &Response{
				Headers: Headers(headers),
				Body:    &Body{Reader: source, limit: -1},
				Client:  NewClient(),
			}

			if err := decodeBodyMW(response); err != nil {
				t.Fatal(err)
			}
			body := response.Body.Bytes()
			if body.IsErr() {
				t.Fatal(body.Err())
			}
			if got := body.Ok().String().Std(); got != payload {
				t.Fatalf("body = %q, want %q", got, payload)
			}
			if !source.closed {
				t.Fatal("compressed response decoder did not close its source body")
			}
		})
	}
}

var _ io.ReadCloser = (*sourceCloseProbe)(nil)
