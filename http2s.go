package surf

import (
	"gitlab.com/x0xO/http"
	"gitlab.com/x0xO/http2"
)

// http2s represents HTTP/2 settings for configuring an Options object.
// https://httpwg.org/specs/rfc7540.html#iana-settings
type http2s struct {
	opt                  *Options
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
func (h *http2s) HeaderTableSize(size uint32) *http2s {
	h.headerTableSize = size
	return h
}

// EnablePush enables HTTP/2 server push functionality.
func (h *http2s) EnablePush(size uint32) *http2s {
	h.usePush = true
	h.enablePush = size
	return h
}

// MaxConcurrentStreams sets the maximum number of concurrent streams in HTTP/2.
func (h *http2s) MaxConcurrentStreams(size uint32) *http2s {
	h.maxConcurrentStreams = size
	return h
}

// InitialWindowSize sets the initial window size for HTTP/2 streams.
func (h *http2s) InitialWindowSize(size uint32) *http2s {
	h.initialWindowSize = size
	return h
}

// MaxFrameSize sets the maximum frame size for HTTP/2 frames.
func (h *http2s) MaxFrameSize(size uint32) *http2s {
	h.maxFrameSize = size
	return h
}

// MaxHeaderListSize sets the maximum size of the header list in HTTP/2.
func (h *http2s) MaxHeaderListSize(size uint32) *http2s {
	h.maxHeaderListSize = size
	return h
}

// ConnectionFlow sets the flow control for the HTTP/2 connection.
func (h *http2s) ConnectionFlow(size uint32) *http2s {
	h.connectionFlow = size
	return h
}

// PriorityParam sets the priority parameter for HTTP/2.
func (h *http2s) PriorityParam(priorityParam http2.PriorityParam) *http2s {
	h.priorityParam = priorityParam
	return h
}

// PriorityFrames sets the priority frames for HTTP/2.
func (h *http2s) PriorityFrames(priorityFrames []http2.PriorityFrame) *http2s {
	h.priorityFrames = priorityFrames
	return h
}

// Set applies the accumulated HTTP/2 settings to the Options object.
// It configures the HTTP/2 settings for the surf client.
// It returns the Options object with the applied settings.
func (h *http2s) Set() *Options {
	if h.opt.forseHTTP1 {
		return h.opt
	}

	return h.opt.addcliMW(func(c *Client) {
		t1 := c.GetTransport().(*http.Transport)
		t1.ForceAttemptHTTP2 = true

		t2, err := http2.ConfigureTransports(t1)
		if err != nil {
			return
		}

		t2.Settings = []http2.Setting{}

		if h.headerTableSize != 0 {
			t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingHeaderTableSize, Val: h.headerTableSize})
		}

		if h.usePush {
			t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingEnablePush, Val: h.enablePush})
		}

		if h.maxConcurrentStreams != 0 {
			t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: h.maxConcurrentStreams})
		}

		if h.initialWindowSize != 0 {
			t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingInitialWindowSize, Val: h.initialWindowSize})
		}

		if h.maxFrameSize != 0 {
			t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingMaxFrameSize, Val: h.maxFrameSize})
		}

		if h.maxHeaderListSize != 0 {
			t2.Settings = append(t2.Settings, http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: h.maxHeaderListSize})
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
	})
}
