package surf

import (
	"github.com/enetx/http"
	"github.com/enetx/http2"
)

// HTTP2Settings represents HTTP/2 settings.
// https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html
type HTTP2Settings struct {
	builder              *Builder
	priorityFrames       []http2.PriorityFrame
	priorityParam        http2.PriorityParam
	headerTableSize      uint32
	enablePush           uint32
	maxConcurrentStreams uint32
	initialWindowSize    uint32
	maxFrameSize         uint32
	maxHeaderListSize    uint32
	connectionFlow       uint32
	usePush              bool
}

// HeaderTableSize sets the header table size for HTTP/2 settings.
func (h *HTTP2Settings) HeaderTableSize(size uint32) *HTTP2Settings {
	h.headerTableSize = size
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
	if h.builder.forseHTTP1 {
		return h.builder
	}

	return h.builder.addCliMW(func(c *Client) error {
		t1, ok := c.GetTransport().(*http.Transport)
		if !ok {
			return nil
		}

		t1.ForceAttemptHTTP2 = true
		t2, err := http2.ConfigureTransports(t1)
		if err != nil {
			return err
		}

		appendSetting := func(id http2.SettingID, val uint32) {
			if val != 0 || (id == http2.SettingEnablePush && h.usePush) {
				t2.Settings = append(t2.Settings, http2.Setting{ID: id, Val: val})
			}
		}

		settings := [...]struct {
			id  http2.SettingID
			val uint32
		}{
			{http2.SettingHeaderTableSize, h.headerTableSize},
			{http2.SettingEnablePush, h.enablePush},
			{http2.SettingMaxConcurrentStreams, h.maxConcurrentStreams},
			{http2.SettingInitialWindowSize, h.initialWindowSize},
			{http2.SettingMaxFrameSize, h.maxFrameSize},
			{http2.SettingMaxHeaderListSize, h.maxHeaderListSize},
		}

		for _, s := range settings {
			appendSetting(s.id, s.val)
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

		t1.H2transport = t2
		c.transport = t1

		return nil
	}, 0)
}
