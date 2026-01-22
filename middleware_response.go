package surf

import (
	"compress/zlib"
	"fmt"
	"io"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/surf/header"
)

// webSocketUpgradeErrorMW detects and handles WebSocket upgrade responses.
// Returns an error when a response indicates a successful WebSocket protocol upgrade
// (HTTP 101 Switching Protocols with Upgrade: websocket header).
// This allows special handling of WebSocket connections which require different processing.
func webSocketUpgradeErrorMW(r *Response) error {
	if r == nil ||
		r.StatusCode != http.StatusSwitchingProtocols {
		return nil
	}

	if r.Headers.Get(header.UPGRADE).Lower() != "websocket" ||
		r.Headers.Get(header.CONNECTION).Lower() != "upgrade" {
		return nil
	}

	method := "UNKNOWN"
	if r.request != nil && r.request.request != nil && r.request.request.Method != "" {
		method = r.request.request.Method
	}

	var url string

	if r.URL != nil {
		url = r.URL.String()
	} else if r.request != nil && r.request.request != nil && r.request.request.URL != nil {
		url = r.request.request.URL.String()
	}

	return &ErrWebSocketUpgrade{fmt.Sprintf(`%s "%s" error:`, method, url)}
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
	if r.builder != nil && r.builder.disableCompression {
		return nil
	}

	if r.Body == nil || r.Body.Reader == nil {
		return nil
	}

	encoding := r.Headers.Get(header.CONTENT_ENCODING)
	if encoding.IsEmpty() {
		return nil
	}

	var reader g.Result[io.ReadCloser]

	switch encoding.Lower() {
	case "deflate":
		reader = g.ResultOf(zlib.NewReader(r.Body.Reader))
	case "gzip":
		reader = acquireGzipReader(r.Body.Reader)
	case "br":
		reader = acquireBrotliReader(r.Body.Reader)
	case "zstd":
		reader = acquireZstdReader(r.Body.Reader)
	default:
		return nil
	}

	if reader.IsErr() {
		return reader.Err()
	}

	r.Body.Reader = reader.Ok()
	r.Headers.Del(header.CONTENT_ENCODING)
	r.Headers.Del(header.CONTENT_LENGTH)
	r.ContentLength = -1

	return nil
}
