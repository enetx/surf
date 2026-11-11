package surf

import "github.com/enetx/quic-go/http3"

type (
	QPACKHuffmanMode  = http3.QPACKHuffmanMode
	QPACKIndexingMode = http3.QPACKIndexingMode
)

const (
	QPACKHuffmanDefault = http3.QPACKHuffmanDefault
	QPACKHuffmanAuto    = http3.QPACKHuffmanAuto
	QPACKHuffmanAlways  = http3.QPACKHuffmanAlways
	QPACKHuffmanNever   = http3.QPACKHuffmanNever
	QPACKIndexAll       = http3.QPACKIndexAll
	QPACKIndexNewNames  = http3.QPACKIndexNewNames
	QPACKIndexNone      = http3.QPACKIndexNone
)

// QpackDynamicTable enables request compression using the peer's dynamic table.
// QpackEncoderTableCapacity sets the local budget; peer SETTINGS cap that budget
// and the number of streams that may reference unacknowledged insertions.
func (h *HTTP3Settings) QpackDynamicTable(enabled bool) *HTTP3Settings {
	h.qpack().DynamicTable = enabled
	return h
}

// QpackHuffman selects native/always, strictly shorter, or raw string encoding.
func (h *HTTP3Settings) QpackHuffman(mode QPACKHuffmanMode) *HTTP3Settings {
	h.qpack().Huffman = mode
	return h
}

// QpackIndexing selects insertion of all eligible fields, only new names, or no
// new entries. Existing dynamic entries remain usable unless never indexed.
func (h *HTTP3Settings) QpackIndexing(mode QPACKIndexingMode) *HTTP3Settings {
	h.qpack().Indexing = mode
	return h
}

// QpackIndexingPolicy optionally filters new insertions by lowercase name/value.
// The callback may run concurrently on different connections and must not reenter
// the transport. Nil removes the filter. Never-index fields are always excluded.
func (h *HTTP3Settings) QpackIndexingPolicy(policy func(name, value string) bool) *HTTP3Settings {
	h.qpack().IndexingPolicy = policy
	return h
}

// QpackDrainingFraction reserves a fraction [0,1] of the table for eviction.
// Old exact entries may be duplicated instead of acquiring new references.
func (h *HTTP3Settings) QpackDrainingFraction(fraction float64) *HTTP3Settings {
	h.qpack().DrainingFraction = fraction
	return h
}

// QpackPostBaseReferences fixes Base before a section's insertions, allowing
// post-base references. False selects Base equal to Required Insert Count.
func (h *HTTP3Settings) QpackPostBaseReferences(enabled bool) *HTTP3Settings {
	h.qpack().PostBaseReferences = enabled
	return h
}

// QpackLiteralInsertNames sends names literally in Insert instructions instead
// of referencing existing static/dynamic names.
func (h *HTTP3Settings) QpackLiteralInsertNames(enabled bool) *HTTP3Settings {
	h.qpack().LiteralInsertNames = enabled
	return h
}

// QpackStopOnInsertionFailure stops new insertion attempts for the rest of a
// section after the first entry cannot fit. Existing references remain usable.
func (h *HTTP3Settings) QpackStopOnInsertionFailure(enabled bool) *HTTP3Settings {
	h.qpack().StopOnInsertionFailure = enabled
	return h
}

// QpackMaxTrackedSections bounds outstanding dynamic header/trailer sections.
// At the bound new sections use static encoding. Zero selects the default 4096.
func (h *HTTP3Settings) QpackMaxTrackedSections(limit uint64) *HTTP3Settings {
	h.qpack().MaxTrackedSections = limit
	return h
}

// QpackEncoderZeroCapacity sends an explicit zero capacity instruction when the
// peer offers no dynamic table, initializing an otherwise lazy encoder stream.
func (h *HTTP3Settings) QpackEncoderZeroCapacity(enabled bool) *HTTP3Settings {
	h.qpack().EncoderZeroCapacity = enabled
	return h
}

// QpackEncoderCapacityRequiresSetting keeps an omitted peer capacity distinct
// from an explicit zero. Zero announcements still use QpackEncoderZeroCapacity.
func (h *HTTP3Settings) QpackEncoderCapacityRequiresSetting(enabled bool) *HTTP3Settings {
	h.qpack().EncoderCapacityRequiresSetting = enabled
	return h
}
