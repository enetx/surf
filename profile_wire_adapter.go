package surf

import (
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/profiles"
)

func (a h2adapter) StreamReceiveWindow(n uint32) profiles.H2Config {
	a.s.StreamReceiveWindow(n)
	return a
}

func (a h2adapter) ReceiveWindowUpdatePolicy(policy func(http2.ReceiveWindowUpdateInfo) bool) profiles.H2Config {
	a.s.ReceiveWindowUpdatePolicy(policy)
	return a
}

func (a h2adapter) MaxEncoderHeaderTableSize(v uint32) profiles.H2Config {
	a.s.MaxEncoderHeaderTableSize(v)
	return a
}

func (a h2adapter) HpackPolicy(v func(string, string) http2.HPACKRepresentation) profiles.H2Config {
	a.s.HpackPolicy(v)
	return a
}

func (a h2adapter) HpackIndexingLimit(v func(uint32) uint32) profiles.H2Config {
	a.s.HpackIndexingLimit(v)
	return a
}

func (a h2adapter) HpackHuffman(v http2.HPACKHuffmanMode) profiles.H2Config {
	a.s.HpackHuffman(v)
	return a
}

func (a h2adapter) HpackDeduplicateTableSizeUpdates(v bool) profiles.H2Config {
	a.s.HpackDeduplicateTableSizeUpdates(v)
	return a
}

func (a h2adapter) HpackNameReferencePolicy(v http2.HPACKNameReferencePolicy) profiles.H2Config {
	a.s.HpackNameReferencePolicy(v)
	return a
}

func (a h2adapter) HpackRepresentation(n string, v http2.HPACKRepresentation) profiles.H2Config {
	a.s.HpackRepresentation(n, v)
	return a
}

func (a h2adapter) HpackDefaultRepresentation(v http2.HPACKRepresentation) profiles.H2Config {
	a.s.HpackDefaultRepresentation(v)
	return a
}

func (a h2adapter) HeaderPriority(v func(http2.PriorityRequest) http2.PriorityParam) profiles.H2Config {
	a.s.HeaderPriority(v)
	return a
}

func (a h2adapter) ChainStreamDependencies(v bool) profiles.H2Config {
	a.s.ChainStreamDependencies(v)
	return a
}

func (a h3adapter) QpackSplitCookies(v bool) profiles.H3Config { a.s.QpackSplitCookies(v); return a }

func (a h3adapter) QpackNeverIndex(v ...string) profiles.H3Config {
	a.s.QpackNeverIndex(v...)
	return a
}

func (a h3adapter) QpackDynamicTable(v bool) profiles.H3Config {
	a.s.QpackDynamicTable(v)
	return a
}

func (a h3adapter) QpackHuffman(v http3.QPACKHuffmanMode) profiles.H3Config {
	a.s.QpackHuffman(v)
	return a
}

func (a h3adapter) QpackIndexing(v http3.QPACKIndexingMode) profiles.H3Config {
	a.s.QpackIndexing(v)
	return a
}

func (a h3adapter) QpackIndexingPolicy(v func(string, string) bool) profiles.H3Config {
	a.s.QpackIndexingPolicy(v)
	return a
}

func (a h3adapter) QpackDrainingFraction(v float64) profiles.H3Config {
	a.s.QpackDrainingFraction(v)
	return a
}

func (a h3adapter) QpackPostBaseReferences(v bool) profiles.H3Config {
	a.s.QpackPostBaseReferences(v)
	return a
}

func (a h3adapter) QpackLiteralInsertNames(v bool) profiles.H3Config {
	a.s.QpackLiteralInsertNames(v)
	return a
}

func (a h3adapter) QpackStopOnInsertionFailure(v bool) profiles.H3Config {
	a.s.QpackStopOnInsertionFailure(v)
	return a
}

func (a h3adapter) QpackMaxTrackedSections(v uint64) profiles.H3Config {
	a.s.QpackMaxTrackedSections(v)
	return a
}

func (a h3adapter) QpackEncoderZeroCapacity(v bool) profiles.H3Config {
	a.s.QpackEncoderZeroCapacity(v)
	return a
}

func (a h3adapter) QpackEncoderCapacityRequiresSetting(v bool) profiles.H3Config {
	a.s.QpackEncoderCapacityRequiresSetting(v)
	return a
}

func (a h3adapter) PriorityUpdates(v bool) profiles.H3Config { a.s.PriorityUpdates(v); return a }

func (a h3adapter) ControlGreaseFramesFactory(v func() ([]http3.GreaseFrame, error)) profiles.H3Config {
	a.s.ControlGreaseFramesFactory(v)
	return a
}

func (a h3adapter) RequestGreaseFramesFactory(v func(*http.Request) ([]http3.GreaseFrame, error)) profiles.H3Config {
	a.s.RequestGreaseFramesFactory(v)
	return a
}

func (a h3adapter) RequestBodyBufferSize(v int) profiles.H3Config {
	a.s.RequestBodyBufferSize(v)
	return a
}

func (a h3adapter) RequestBodyBufferSizePolicy(v func(int64) int) profiles.H3Config {
	a.s.RequestBodyBufferSizePolicy(v)
	return a
}

func (a h3adapter) MaxDataFrameSize(v int) profiles.H3Config { a.s.MaxDataFrameSize(v); return a }

func (a h3adapter) CompactPriorityUpdates(v bool) profiles.H3Config {
	a.s.CompactPriorityUpdates(v)
	return a
}

func (a h3adapter) EarlyData(v bool) profiles.H3Config { a.s.EarlyData(v); return a }

func (a h3adapter) RequestBodyFirstReadSizePolicy(v func(http3.RequestBodyReadInfo) int) profiles.H3Config {
	a.s.RequestBodyFirstReadSizePolicy(v)
	return a
}

func (a h3adapter) CoalesceInitialSettings(enabled bool) profiles.H3Config {
	a.s.CoalesceInitialSettings(enabled)
	return a
}

func (a h3adapter) CoalesceRequestHeaders(enabled bool) profiles.H3Config {
	a.s.CoalesceRequestHeaders(enabled)
	return a
}
