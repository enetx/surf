package surf

import (
	"slices"

	"github.com/enetx/quic-go/http3"
)

// QPACKStreamType identifies an HTTP/3 QPACK unidirectional stream.
type QPACKStreamType = http3.QPACKStreamType

const (
	QPACKEncoderStream = http3.QPACKEncoderStream
	QPACKDecoderStream = http3.QPACKDecoderStream
)

// QPACKCapacityTiming controls when an outgoing capacity instruction is queued.
type QPACKCapacityTiming = http3.QPACKCapacityTiming

const (
	QPACKCapacityOnSettings    = http3.QPACKCapacityOnSettings
	QPACKCapacityBeforeHeaders = http3.QPACKCapacityBeforeHeaders
)

func (h *HTTP3Settings) qpack() *http3.QPACKConfig {
	if h.qpackConfig == nil {
		h.qpackConfig = &http3.QPACKConfig{}
	}
	return h.qpackConfig
}

// QpackStreamOrder reserves QPACK streams after the control stream in the given
// order, while peer credit permits. Omitted streams open on demand. Input is copied.
func (h *HTTP3Settings) QpackStreamOrder(order ...QPACKStreamType) *HTTP3Settings {
	h.qpack().StreamOrder = slices.Clone(order)
	return h
}

// QpackEagerStreamTypes queues stream type bytes at initialization for streams
// listed in QpackStreamOrder. False sends each type with its first instruction.
func (h *HTTP3Settings) QpackEagerStreamTypes(eager bool) *HTTP3Settings {
	h.qpack().EagerStreamTypes = eager
	return h
}

// QpackEncoderTableCapacity limits the capacity announced for request encoding.
// The announcement is capped by peer SETTINGS; zero disables it. This does not
// enable dynamic request compression. QpackMaxTableCapacity separately configures
// the receive-side dynamic table advertised in our own SETTINGS.
func (h *HTTP3Settings) QpackEncoderTableCapacity(capacity uint64) *HTTP3Settings {
	h.qpack().EncoderTableCapacity = capacity
	return h
}

// QpackEncoderCapacityTiming queues capacity after peer SETTINGS or when encoding
// the next outgoing HEADERS block. It does not wait for server SETTINGS or force
// network delivery order between independent QUIC streams.
func (h *HTTP3Settings) QpackEncoderCapacityTiming(timing QPACKCapacityTiming) *HTTP3Settings {
	h.qpack().EncoderCapacityTiming = timing
	return h
}
