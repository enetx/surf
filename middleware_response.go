package surf

import (
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"sync"

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

// Pools for reusing decompression resources to reduce allocations.
var (
	// zstdDecoderPool pools zstd.Decoder instances.
	zstdDecoderPool = sync.Pool{
		New: func() any {
			dec, _ := zstd.NewReader(nil)
			return dec
		},
	}

	// gzipReaderPool pools gzip.Reader instances.
	gzipReaderPool = sync.Pool{
		New: func() any {
			return new(gzip.Reader)
		},
	}
)

type (
	// zstdReadCloser wraps a zstd decoder and returns it to the pool on Close.
	zstdReadCloser struct {
		io.ReadCloser
		dec *zstd.Decoder
	}

	// gzipReadCloser wraps a gzip reader and returns it to the pool on Close.
	gzipReadCloser struct {
		*gzip.Reader
	}
)

// Close closes the underlying reader and returns the decoder to the pool.
func (z *zstdReadCloser) Close() error {
	err := z.ReadCloser.Close()
	zstdDecoderPool.Put(z.dec)
	return err
}

// Close closes the reader and returns it to the pool.
func (g *gzipReadCloser) Close() error {
	err := g.Reader.Close()
	gzipReaderPool.Put(g.Reader)
	return err
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
	if r.Body == nil || r.Body.Reader == nil {
		return nil
	}

	encoding := r.Headers.Get(header.CONTENT_ENCODING)
	if encoding.Empty() {
		return nil
	}

	var (
		reader io.ReadCloser
		err    error
	)

	switch encoding.Lower() {
	case "deflate":
		reader, err = zlib.NewReader(r.Body.Reader)
	case "gzip":
		gr := gzipReaderPool.Get().(*gzip.Reader)
		if err := gr.Reset(r.Body.Reader); err != nil {
			gzipReaderPool.Put(gr)
			return err
		}
		reader = &gzipReadCloser{Reader: gr}
	case "br":
		reader = io.NopCloser(brotli.NewReader(r.Body.Reader))
	case "zstd":
		dec := zstdDecoderPool.Get().(*zstd.Decoder)
		if err := dec.Reset(r.Body.Reader); err != nil {
			zstdDecoderPool.Put(dec)
			return err
		}
		reader = &zstdReadCloser{
			ReadCloser: dec.IOReadCloser(),
			dec:        dec,
		}
	default:
		return nil
	}

	if err == nil && reader != nil {
		r.Body.Reader = reader
		r.Headers.Del(header.CONTENT_ENCODING)
		r.Headers.Del(header.CONTENT_LENGTH)
		r.ContentLength = -1
	}

	return err
}
