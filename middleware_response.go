package surf

import (
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
	"github.com/klauspost/compress/zstd"
)

func closeIdleConnectionsMW(r *Response) error {
	r.cli.CloseIdleConnections()
	return nil
}

func webSocketUpgradeErrorMW(r *Response) error {
	if r.StatusCode == http.StatusSwitchingProtocols && r.Headers.Get(header.UPGRADE) == "websocket" {
		return &ErrWebSocketUpgrade{fmt.Sprintf(`%s "%s" error:`, r.request.request.Method, r.URL.String())}
	}

	return nil
}

// decodeBodyMW decodes the compressed body content based on the specified compression method.
// It supports decoding content compressed using deflate, gzip, or brotli algorithms.
// The mw updates the body content to its decompressed form if decoding is successful.
func decodeBodyMW(r *Response) error {
	if r.Body == nil {
		return nil
	}

	var (
		reader io.ReadCloser
		err    error
	)

	switch r.Headers.Get(header.CONTENT_ENCODING) {
	case "deflate":
		reader, err = zlib.NewReader(r.Body.Reader)
	case "gzip":
		reader, err = gzip.NewReader(r.Body.Reader)
	case "br":
		reader = io.NopCloser(brotli.NewReader(r.Body.Reader))
	case "zstd":
		decoder, err := zstd.NewReader(r.Body.Reader)
		if err != nil {
			return err
		}

		reader = decoder.IOReadCloser()
	}

	if err == nil && reader != nil {
		r.Body.Reader = reader
	}

	return err
}
