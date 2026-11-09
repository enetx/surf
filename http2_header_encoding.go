package surf

import (
	"strings"

	"github.com/enetx/http/http2"
)

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
