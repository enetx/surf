package surf

import (
	"bytes"
	"compress/gzip"
	"io"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/enetx/g"
	"github.com/klauspost/compress/zstd"
)

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

	// brotliReaderPool pools brotli.Reader instances.
	brotliReaderPool = sync.Pool{
		New: func() any {
			return brotli.NewReader(nil)
		},
	}

	// bodyBufferPool pools bytes.Buffer for reading response bodies.
	bodyBufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
)

// zstdReadCloser wraps a zstd decoder and returns it to the pool on Close.
type zstdReadCloser struct {
	io.ReadCloser
	dec *zstd.Decoder
}

// Close closes the underlying reader and returns the decoder to the pool.
func (zr *zstdReadCloser) Close() error {
	err := zr.ReadCloser.Close()
	zstdDecoderPool.Put(zr.dec)
	return err
}

// gzipReadCloser wraps a gzip reader and returns it to the pool on Close.
type gzipReadCloser struct {
	*gzip.Reader
}

// Close closes the reader and returns it to the pool.
func (gr *gzipReadCloser) Close() error {
	err := gr.Reader.Close()
	gzipReaderPool.Put(gr.Reader)
	return err
}

// brotliReadCloser wraps a brotli reader and returns it to the pool on Close.
type brotliReadCloser struct {
	*brotli.Reader
}

// Close returns the reader to the pool.
func (br *brotliReadCloser) Close() error {
	brotliReaderPool.Put(br.Reader)
	return nil
}

// acquireGzipReader gets a gzip.Reader from the pool and resets it with the provided reader.
// Returns the reader wrapped in gzipReadCloser for automatic pool management.
func acquireGzipReader(r io.Reader) g.Result[io.ReadCloser] {
	gr := gzipReaderPool.Get().(*gzip.Reader)
	if err := gr.Reset(r); err != nil {
		gzipReaderPool.Put(gr)
		return g.Err[io.ReadCloser](err)
	}

	return g.Ok[io.ReadCloser](&gzipReadCloser{Reader: gr})
}

// acquireBrotliReader gets a brotli.Reader from the pool and resets it with the provided reader.
// Returns the reader wrapped in brotliReadCloser for automatic pool management.
func acquireBrotliReader(r io.Reader) g.Result[io.ReadCloser] {
	br := brotliReaderPool.Get().(*brotli.Reader)
	if err := br.Reset(r); err != nil {
		brotliReaderPool.Put(br)
		return g.Err[io.ReadCloser](err)
	}

	return g.Ok[io.ReadCloser](&brotliReadCloser{Reader: br})
}

// acquireZstdReader gets a zstd.Decoder from the pool and resets it with the provided reader.
// Returns the decoder wrapped in zstdReadCloser for automatic pool management.
func acquireZstdReader(r io.Reader) g.Result[io.ReadCloser] {
	dec := zstdDecoderPool.Get().(*zstd.Decoder)
	if err := dec.Reset(r); err != nil {
		zstdDecoderPool.Put(dec)
		return g.Err[io.ReadCloser](err)
	}

	return g.Ok[io.ReadCloser](&zstdReadCloser{
		ReadCloser: dec.IOReadCloser(),
		dec:        dec,
	})
}
