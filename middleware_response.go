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

// closeIdleConnectionsMW forces the client to close idle connections after each response.
// This middleware is useful when using non-singleton clients to prevent connection leaks
// and ensure clean resource management. Particularly important for JA3 fingerprinting scenarios.
func closeIdleConnectionsMW(r *Response) error {
	r.cli.CloseIdleConnections()
	return nil
}

// webSocketUpgradeErrorMW detects and handles WebSocket upgrade responses.
// Returns an error when a response indicates a successful WebSocket protocol upgrade
// (HTTP 101 Switching Protocols with Upgrade: websocket header).
// This allows special handling of WebSocket connections which require different processing.
func webSocketUpgradeErrorMW(r *Response) error {
	if r.StatusCode == http.StatusSwitchingProtocols && r.Headers.Get(header.UPGRADE) == "websocket" {
		return &ErrWebSocketUpgrade{fmt.Sprintf(`%s "%s" error:`, r.request.request.Method, r.URL.String())}
	}

	return nil
}

// decodeBodyMW automatically decompresses response bodies based on Content-Encoding header.
// Supports multiple compression algorithms:
// - deflate: DEFLATE compression (zlib format)
// - gzip: GZIP compression
// - br: Brotli compression
// - zstd: Zstandard compression
// Updates the response body reader to provide decompressed content transparently.
// Returns an error if decompression fails, otherwise the body can be read normally.
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
