package surf

import (
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
)

// zstdReadCloser wraps a zstd decoder and returns it to the pool on Close.
type zstdReadCloser struct {
	dec *zstd.Decoder
}

// Read reads decompressed data from the decoder.
func (zr *zstdReadCloser) Read(p []byte) (int, error) {
	return zr.dec.Read(p)
}

// Close resets the decoder and returns it to the pool.
func (zr *zstdReadCloser) Close() error {
	if err := zr.dec.Reset(nil); err != nil {
		return err
	}

	zstdDecoderPool.Put(zr.dec)
	return nil
}

// gzipReadCloser wraps a gzip reader and returns it to the pool on Close.
type gzipReadCloser struct {
	*gzip.Reader
}

// Close closes the reader and returns it to the pool.
func (gr *gzipReadCloser) Close() error {
	if err := gr.Reader.Close(); err != nil {
		return err
	}

	gzipReaderPool.Put(gr.Reader)
	return nil
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

	return g.Ok[io.ReadCloser](&zstdReadCloser{dec: dec})
}
