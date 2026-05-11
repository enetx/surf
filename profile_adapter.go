package surf

import (
	"github.com/enetx/http2"
	"github.com/enetx/surf/profiles"
)

// h2adapter wraps *HTTP2Settings to satisfy profiles.H2Config (which returns the interface type
// instead of *HTTP2Settings, so direct method satisfaction is impossible). Each method delegates
// to the underlying *HTTP2Settings and returns the adapter to keep the chain fluent.
type h2adapter struct{ s *HTTP2Settings }

func (a h2adapter) HeaderTableSize(v uint32) profiles.H2Config {
	a.s.HeaderTableSize(v)
	return a
}

func (a h2adapter) EnablePush(v uint32) profiles.H2Config {
	a.s.EnablePush(v)
	return a
}

func (a h2adapter) MaxConcurrentStreams(v uint32) profiles.H2Config {
	a.s.MaxConcurrentStreams(v)
	return a
}

func (a h2adapter) InitialWindowSize(v uint32) profiles.H2Config {
	a.s.InitialWindowSize(v)
	return a
}

func (a h2adapter) MaxFrameSize(v uint32) profiles.H2Config {
	a.s.MaxFrameSize(v)
	return a
}

func (a h2adapter) MaxHeaderListSize(v uint32) profiles.H2Config {
	a.s.MaxHeaderListSize(v)
	return a
}

func (a h2adapter) NoRFC7540Priorities(v uint32) profiles.H2Config {
	a.s.NoRFC7540Priorities(v)
	return a
}

func (a h2adapter) ConnectionFlow(v uint32) profiles.H2Config {
	a.s.ConnectionFlow(v)
	return a
}

func (a h2adapter) InitialStreamID(v uint32) profiles.H2Config {
	a.s.InitialStreamID(v)
	return a
}

func (a h2adapter) PriorityParam(v http2.PriorityParam) profiles.H2Config {
	a.s.PriorityParam(v)
	return a
}

func (a h2adapter) PriorityFrames(v []http2.PriorityFrame) profiles.H2Config {
	a.s.PriorityFrames(v)
	return a
}

// h3adapter wraps *HTTP3Settings to satisfy profiles.H3Config.
type h3adapter struct{ s *HTTP3Settings }

func (a h3adapter) QpackMaxTableCapacity(v uint64) profiles.H3Config {
	a.s.QpackMaxTableCapacity(v)
	return a
}

func (a h3adapter) MaxFieldSectionSize(v uint64) profiles.H3Config {
	a.s.MaxFieldSectionSize(v)
	return a
}

func (a h3adapter) QpackBlockedStreams(v uint64) profiles.H3Config {
	a.s.QpackBlockedStreams(v)
	return a
}

func (a h3adapter) EnableConnectProtocol(v uint64) profiles.H3Config {
	a.s.EnableConnectProtocol(v)
	return a
}

func (a h3adapter) SettingsH3Datagram(v uint64) profiles.H3Config {
	a.s.SettingsH3Datagram(v)
	return a
}

func (a h3adapter) H3Datagram(v uint64) profiles.H3Config {
	a.s.H3Datagram(v)
	return a
}

func (a h3adapter) EnableWebtransport(v uint64) profiles.H3Config {
	a.s.EnableWebtransport(v)
	return a
}

func (a h3adapter) Grease() profiles.H3Config {
	a.s.Grease()
	return a
}
