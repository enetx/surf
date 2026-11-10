package surf

// RequestBodyBufferSize sets reads from HTTP/3 request bodies (0 uses 8 KiB).
// It clears a previously configured size policy. Sizes must be in [0, 16 MiB].
func (h *HTTP3Settings) RequestBodyBufferSize(size int) *HTTP3Settings {
	h.wire().RequestBodyBufferSize = size
	h.wire().RequestBodyBufferSizePolicy = nil
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
