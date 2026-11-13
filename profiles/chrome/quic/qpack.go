package quic

import (
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/profiles"
)

// ConfigureQPACK follows Chromium's stream reservation and deferred flush policy.
// Creating a stream does not send its type until the first instruction is queued.
func ConfigureQPACK(h profiles.H3Config) {
	// Cookie splitting belongs to the HTTP/3 header encoder. Initial priority
	// updates belong to QuicSpdyStream and are separate from GREASE frames.
	// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/qpack/value_splitting_header_list.cc
	// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/http/quic_spdy_stream.cc
	// Priority fields use QUICHE structured-header dictionary serialization.
	// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_stream_priority.cc
	// QUICHE indexes eligible fields, drains the oldest quarter of the table,
	// and uses Huffman only when shorter. Base equals Required Insert Count.
	// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/qpack/qpack_encoder.cc
	// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/qpack/qpack_instruction_encoder.cc
	// SendInitialData runs as soon as application encryption is established.
	// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/http/quic_spdy_session.cc
	h.CoalesceInitialSettings(true).CoalesceRequestHeaders(true).QpackDynamicTable(true).
		QpackHuffman(http3.QPACKHuffmanAuto).
		QpackIndexing(http3.QPACKIndexAll).
		QpackIndexingPolicy(nil).
		// QUICHE maps the resumption SETTINGS mismatch to H3_SETTINGS_ERROR.
		// https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_error_codes.cc
		QpackResumptionErrorCode(func(uint64, uint64) http3.ErrCode { return http3.ErrCodeSettingsError }).
		QpackDrainingFraction(.25).
		QpackPostBaseReferences(false).
		QpackLiteralInsertNames(false).
		QpackStopOnInsertionFailure(false).
		QpackMaxTrackedSections(0).
		// OnSetting handles an explicit zero, but no callback occurs for an
		// omitted capacity. The lazy stream stays silent in the latter case.
		QpackEncoderZeroCapacity(true).QpackEncoderCapacityRequiresSetting(true).
		QpackNeverIndex().
		QpackSplitCookies(true).
		PriorityUpdates(true).
		CompactPriorityUpdates(false).
		ControlGreaseFramesFactory(NewControlGreaseFrames).
		QpackStreamOrder(http3.QPACKDecoderStream, http3.QPACKEncoderStream).
		QpackEagerStreamTypes(false).
		QpackEncoderTableCapacity(65536).
		QpackEncoderCapacityTiming(http3.QPACKCapacityBeforeHeaders)
}
