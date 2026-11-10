package main

import (
	"fmt"

	"github.com/enetx/http/http2"
)

// The capture peer must obey the browser's credit and frame-size limits itself,
// otherwise a bulk response measures a malformed server rather than the client.
type h2CaptureFlow struct {
	fr                  *http2.Framer
	connection, initial int64
	streams             map[uint32]int64
	pending             []http2.Frame
}

func newH2CaptureFlow(fr *http2.Framer) *h2CaptureFlow {
	return &h2CaptureFlow{fr: fr, connection: 65535, initial: 65535, streams: make(map[uint32]int64)}
}

func (f *h2CaptureFlow) readFrame() (http2.Frame, error) {
	if len(f.pending) == 0 {
		return f.fr.ReadFrame()
	}
	frame := f.pending[0]
	f.pending = f.pending[1:]
	return frame, nil
}

func (f *h2CaptureFlow) control(frame http2.Frame) (bool, error) {
	switch frame := frame.(type) {
	case *http2.SettingsFrame:
		if frame.IsAck() {
			return true, nil
		}
		err := frame.ForeachSetting(func(s http2.Setting) error {
			if err := s.Valid(); err != nil {
				return err
			}
			if s.ID == http2.SettingInitialWindowSize {
				for stream := range f.streams {
					f.streams[stream] += int64(s.Val) - f.initial
				}
				f.initial = int64(s.Val)
			}
			return nil
		})
		if err != nil {
			return true, err
		}
		return true, f.fr.WriteSettingsAck()
	case *http2.WindowUpdateFrame:
		if frame.StreamID == 0 {
			f.connection += int64(frame.Increment)
		} else {
			credit, ok := f.streams[frame.StreamID]
			if !ok {
				credit = f.initial
			}
			f.streams[frame.StreamID] = credit + int64(frame.Increment)
		}
		return true, nil
	case *http2.PingFrame:
		if !frame.IsAck() {
			return true, f.fr.WritePing(true, frame.Data)
		}
		return true, nil
	case *http2.GoAwayFrame:
		return true, fmt.Errorf("capture peer received GOAWAY: %v", frame.ErrCode)
	}
	return false, nil
}

func (f *h2CaptureFlow) writeBody(stream uint32, body []byte) error {
	if len(body) == 0 {
		return f.fr.WriteData(stream, true, nil)
	}
	if _, ok := f.streams[stream]; !ok {
		f.streams[stream] = f.initial
	}
	for len(body) > 0 {
		n := min(int64(len(body)), 16384, f.connection, f.streams[stream])
		if n <= 0 {
			frame, err := f.fr.ReadFrame()
			if err != nil {
				return err
			}
			handled, err := f.control(frame)
			if err != nil {
				return err
			}
			if !handled {
				if len(f.pending) >= 64 {
					return fmt.Errorf("too many pending capture requests")
				}
				f.pending = append(f.pending, frame)
			}
			continue
		}
		if err := f.fr.WriteData(stream, int(n) == len(body), body[:n]); err != nil {
			return err
		}
		body = body[n:]
		f.connection -= n
		f.streams[stream] -= n
	}
	return nil
}
