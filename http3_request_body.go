package surf

import "github.com/enetx/quic-go/http3"

// HTTP3RequestBodyReadInfo contains validated wire fields and the effective buffer size.
type HTTP3RequestBodyReadInfo = http3.RequestBodyReadInfo

// RequestBodyBufferSize sets reads from HTTP/3 request bodies (0 uses 8 KiB).
// It clears previously configured size and first-read policies. Sizes must be in [0, 16 MiB].
func (h *HTTP3Settings) RequestBodyBufferSize(size int) *HTTP3Settings {
	h.wire().RequestBodyBufferSize = size
	h.wire().RequestBodyBufferSizePolicy = nil
	h.wire().RequestBodyFirstReadSizePolicy = nil

	return h
}

// RequestBodyBufferSizePolicy chooses a buffer using ContentLength (-1 when
// unknown). It must be concurrency safe; zero uses 8 KiB. Nil restores the fixed size.
func (h *HTTP3Settings) RequestBodyBufferSizePolicy(policy func(int64) int) *HTTP3Settings {
	h.wire().RequestBodyBufferSizePolicy = policy
	return h
}

// MaxDataFrameSize caps request DATA payloads. Zero preserves one frame per
// body read or Write. This does not set QUIC packet boundaries.
func (h *HTTP3Settings) MaxDataFrameSize(size int) *HTTP3Settings {
	h.wire().MaxDataFrameSize = size
	return h
}

// RequestBodyFirstReadSizePolicy caps the first nonempty HTTP/3 body read.
// Zero restores the normal buffer size; a positive result must not exceed it.
// The callback receives actual outgoing fields, including implicit headers, and
// runs before request bytes or QPACK state changes. It must be concurrency safe.
// Nil clears this policy. It does not change QUIC packet boundaries.
func (h *HTTP3Settings) RequestBodyFirstReadSizePolicy(policy func(HTTP3RequestBodyReadInfo) int) *HTTP3Settings {
	h.wire().RequestBodyFirstReadSizePolicy = policy
	return h
}
