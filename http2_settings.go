package surf

import (
	"fmt"
	"math"
	"strings"

	"github.com/enetx/http"
	"github.com/enetx/http/http2"
)

// HTTP2Settings represents HTTP/2 settings.
// https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html
type HTTP2Settings struct {
	streamReceiveWindow       uint32
	receiveWindowUpdatePolicy func(http2.ReceiveWindowUpdateInfo) bool
	registered                bool
	priorityFrames            []http2.PriorityFrame
	priorityParam             http2.PriorityParam
	builder                   *Builder
	headerTableSize           uint32
	maxConcurrentStreams      uint32
	initialWindowSize         uint32
	maxFrameSize              uint32
	maxHeaderListSize         uint32
	connectionFlow            uint32
	initialStreamID           uint32
	noRFC7540Priorities       uint32
	enablePush                uint32
	usePush                   bool
	hpack                     *http2.HPACKConfig
	headerPriority            func(http2.PriorityRequest) http2.PriorityParam
	chainStreamDependencies   bool
	maxEncoderHeaderTableSize uint32
}

// InitialStreamID sets the initial stream id for HTTP/2 streams.
func (h *HTTP2Settings) InitialStreamID(id uint32) *HTTP2Settings {
	h.initialStreamID = id
	return h
}

// HeaderTableSize sets the header table size for HTTP/2 settings.
func (h *HTTP2Settings) HeaderTableSize(size uint32) *HTTP2Settings {
	h.headerTableSize = size
	return h
}

// MaxEncoderHeaderTableSize bounds the request encoder's table, independently
// of HeaderTableSize (our advertised decoder capacity). Zero retains upstream
// defaults. The native engine supports limits up to math.MaxInt32.
func (h *HTTP2Settings) MaxEncoderHeaderTableSize(size uint32) *HTTP2Settings {
	h.maxEncoderHeaderTableSize = size
	return h
}

// EnablePush enables HTTP/2 server push functionality.
func (h *HTTP2Settings) EnablePush(size uint32) *HTTP2Settings {
	h.usePush = true
	h.enablePush = size
	return h
}

// MaxConcurrentStreams sets the maximum number of concurrent streams in HTTP/2.
func (h *HTTP2Settings) MaxConcurrentStreams(size uint32) *HTTP2Settings {
	h.maxConcurrentStreams = size
	return h
}

// InitialWindowSize sets the initial window size for HTTP/2 streams.
func (h *HTTP2Settings) InitialWindowSize(size uint32) *HTTP2Settings {
	h.initialWindowSize = size
	return h
}

// MaxFrameSize sets the maximum frame size for HTTP/2 frames.
func (h *HTTP2Settings) MaxFrameSize(size uint32) *HTTP2Settings {
	h.maxFrameSize = size
	return h
}

// MaxHeaderListSize sets the maximum size of the header list in HTTP/2.
func (h *HTTP2Settings) MaxHeaderListSize(size uint32) *HTTP2Settings {
	h.maxHeaderListSize = size
	return h
}

// NoRFC7540Priorities disables RFC 7540 priority signaling in HTTP/2.
func (h *HTTP2Settings) NoRFC7540Priorities(size uint32) *HTTP2Settings {
	h.noRFC7540Priorities = size
	return h
}

// ConnectionFlow sets the flow control for the HTTP/2 connection.
func (h *HTTP2Settings) ConnectionFlow(size uint32) *HTTP2Settings {
	h.connectionFlow = size
	return h
}

// PriorityParam sets the priority parameter for HTTP/2.
func (h *HTTP2Settings) PriorityParam(priorityParam http2.PriorityParam) *HTTP2Settings {
	h.priorityParam = priorityParam
	return h
}

// PriorityFrames sets the priority frames for HTTP/2.
func (h *HTTP2Settings) PriorityFrames(priorityFrames []http2.PriorityFrame) *HTTP2Settings {
	h.priorityFrames = priorityFrames
	return h
}

// Set applies the accumulated HTTP/2 settings.
// It configures the HTTP/2 settings for the surf client.
func (h *HTTP2Settings) Set() *Builder {
	if h.registered {
		return h.builder
	}
	h.registered = true
	if h.builder.forceHTTP1 {
		return h.builder
	}

	return h.builder.addCliMW(func(c *Client) error {
		if h.maxEncoderHeaderTableSize > math.MaxInt32 {
			return fmt.Errorf("HTTP/2 encoder table limit exceeds supported range")
		}
		if err := h.hpack.Validate(); err != nil {
			return err
		}

		t1, ok := c.GetTransport().(*http.Transport)
		if !ok {
			return nil
		}

		t1.ForceAttemptHTTP2 = true
		t2, err := http2.ConfigureTransports(t1)
		if err != nil {
			return err
		}

		t2.Settings = make([]http2.Setting, 0, 7)

		appendSetting := func(id http2.SettingID, val uint32) {
			if val != 0 || (id == http2.SettingEnablePush && h.usePush) {
				t2.Settings = append(t2.Settings, http2.Setting{ID: id, Val: val})
			}
		}

		appendSetting(http2.SettingHeaderTableSize, h.headerTableSize)
		appendSetting(http2.SettingEnablePush, h.enablePush)
		appendSetting(http2.SettingMaxConcurrentStreams, h.maxConcurrentStreams)
		appendSetting(http2.SettingInitialWindowSize, h.initialWindowSize)
		appendSetting(http2.SettingMaxFrameSize, h.maxFrameSize)
		appendSetting(http2.SettingMaxHeaderListSize, h.maxHeaderListSize)
		appendSetting(http2.SettingNoRFC7540Priorities, h.noRFC7540Priorities)

		if h.initialStreamID != 0 {
			t2.StreamID = h.initialStreamID
		}

		if h.connectionFlow != 0 {
			t2.ConnectionFlow = h.connectionFlow
		}

		if !h.priorityParam.IsZero() {
			t2.PriorityParam = h.priorityParam
		}

		if h.priorityFrames != nil {
			t2.PriorityFrames = h.priorityFrames
		}

		t2.HPACK = h.hpack.Clone()
		t2.StreamReceiveWindow = h.streamReceiveWindow
		t2.ReceiveWindowUpdatePolicy = h.receiveWindowUpdatePolicy
		t2.MaxEncoderHeaderTableSize = h.maxEncoderHeaderTableSize
		t2.HeaderPriority = h.headerPriority
		t2.ChainStreamDependencies = h.chainStreamDependencies

		c.transport = t1

		return nil
	}, 0)
}

// HPACKRepresentation selects how a request or trailer field is encoded.
type (
	HPACKRepresentation      = http2.HPACKRepresentation
	HPACKHuffmanMode         = http2.HPACKHuffmanMode
	HPACKNameReferencePolicy = http2.HPACKNameReferencePolicy
)

const (
	HPACKDefault              = http2.HPACKDefault
	HPACKWithoutIndexing      = http2.HPACKWithoutIndexing
	HPACKNeverIndex           = http2.HPACKNeverIndex
	HPACKIncrementalIndexing  = http2.HPACKIncrementalIndexing
	HPACKHuffmanDefault       = http2.HPACKHuffmanDefault
	HPACKHuffmanAlways        = http2.HPACKHuffmanAlways
	HPACKHuffmanNever         = http2.HPACKHuffmanNever
	HPACKNameReferenceDefault = http2.HPACKNameReferenceDefault
	HPACKNameReferenceLast    = http2.HPACKNameReferenceLast
	HPACKNameReferenceFirst   = http2.HPACKNameReferenceFirst
)

func (h *HTTP2Settings) hpackConfig() *http2.HPACKConfig {
	if h.hpack == nil {
		h.hpack = &http2.HPACKConfig{}
	}
	return h.hpack
}

// HpackHuffman chooses automatic, always or disabled Huffman string encoding.
func (h *HTTP2Settings) HpackHuffman(mode HPACKHuffmanMode) *HTTP2Settings {
	h.hpackConfig().Huffman = mode
	return h
}

// HpackDeduplicateTableSizeUpdates suppresses updates for repeated peer table
// capacities while retaining pending shrink/grow instructions.
func (h *HTTP2Settings) HpackDeduplicateTableSizeUpdates(enabled bool) *HTTP2Settings {
	h.hpackConfig().DeduplicateTableSizeUpdates = enabled
	return h
}

// HpackNameReferencePolicy controls which matching field name a literal refers to.
func (h *HTTP2Settings) HpackNameReferencePolicy(policy HPACKNameReferencePolicy) *HTTP2Settings {
	h.hpackConfig().NameReferencePolicy = policy
	return h
}

// HpackDefaultRepresentation sets the fallback for fields without an override.
// HPACKDefault retains upstream indexing, table eviction and Huffman behavior.
func (h *HTTP2Settings) HpackDefaultRepresentation(rep HPACKRepresentation) *HTTP2Settings {
	h.hpackConfig().Default = rep
	return h
}

// HpackRepresentation overrides the policy for one field, including pseudo-fields.
func (h *HTTP2Settings) HpackRepresentation(name string, rep HPACKRepresentation) *HTTP2Settings {
	c := h.hpackConfig()
	if c.Representations == nil {
		c.Representations = make(map[string]HPACKRepresentation)
	}
	c.Representations[strings.ToLower(name)] = rep
	return h
}

// HpackPolicy selects representations by field name and value. Per-name
// HpackRepresentation overrides take precedence. The callback must be safe for
// concurrent connections and must not reenter the client.
func (h *HTTP2Settings) HpackPolicy(policy func(name, value string) HPACKRepresentation) *HTTP2Settings {
	h.hpackConfig().Policy = policy
	return h
}

// HpackIndexingLimit bounds new dynamic entries by their HPACK size (including
// 32 bytes of overhead), as a function of the current encoder table capacity.
// Existing exact entries remain reusable. Nil restores the upstream limit.
func (h *HTTP2Settings) HpackIndexingLimit(limit func(tableCapacity uint32) uint32) *HTTP2Settings {
	h.hpackConfig().IndexingLimit = limit
	return h
}

// HeaderPriority selects HTTP/2 HEADERS priority per request. The request is a
// read-only view. The callback must be safe for concurrent connections and must
// not reenter the client. Nil restores PriorityParam.
func (h *HTTP2Settings) HeaderPriority(policy func(http2.PriorityRequest) http2.PriorityParam) *HTTP2Settings {
	h.headerPriority = policy
	return h
}

// ChainStreamDependencies selects the newest still-open earlier stream with
// equal or greater weight as the dependency. Exclusive remains caller-controlled.
func (h *HTTP2Settings) ChainStreamDependencies(enabled bool) *HTTP2Settings {
	h.chainStreamDependencies = enabled
	return h
}

type HTTP2ReceiveWindowUpdateInfo = http2.ReceiveWindowUpdateInfo

// StreamReceiveWindow raises each client-created stream's credit after HEADERS.
// Zero uses InitialWindowSize; a nonzero window must be at least that size.
func (h *HTTP2Settings) StreamReceiveWindow(size uint32) *HTTP2Settings {
	h.streamReceiveWindow = size
	return h
}

// ReceiveWindowUpdatePolicy controls batching of returned HTTP/2 receive credit.
// Nil restores native behavior. The callback runs under the connection lock;
// it must return promptly, be concurrency safe and never reenter the transport.
// Credit is always refreshed when the peer's available window is exhausted.
func (h *HTTP2Settings) ReceiveWindowUpdatePolicy(policy func(HTTP2ReceiveWindowUpdateInfo) bool) *HTTP2Settings {
	h.receiveWindowUpdatePolicy = policy
	return h
}
