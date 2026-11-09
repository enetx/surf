package surf

import (
	"github.com/enetx/http"
	"github.com/enetx/http/http2"
	"github.com/enetx/quic-go/http3"
	"github.com/enetx/surf/profiles"
)

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
func (a h3adapter) PriorityUpdates(v bool) profiles.H3Config { a.s.PriorityUpdates(v); return a }
func (a h3adapter) ControlGreaseFramesFactory(v func() ([]http3.GreaseFrame, error)) profiles.H3Config {
	a.s.ControlGreaseFramesFactory(v)
	return a
}
func (a h3adapter) RequestGreaseFramesFactory(v func(*http.Request) ([]http3.GreaseFrame, error)) profiles.H3Config {
	a.s.RequestGreaseFramesFactory(v)
	return a
}
