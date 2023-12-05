package surf

import (
	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http2"
)

type impersonate struct{ opt *Options }

// Chrome impersonates Chrome browser v.107.
func (im *impersonate) Chrome() *Options {
	// "akamai_fingerprint": "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
	im.opt.JA3().Chrome().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(0).
		MaxConcurrentStreams(1000).
		InitialWindowSize(6291456).
		MaxHeaderListSize(262144).
		ConnectionFlow(15663105).
		PriorityParam(
			http2.PriorityParam{
				StreamDep: 0,
				Exclusive: true,
				Weight:    255,
			}).Set()

	headers := g.NewMapOrd[string, string]().
		Set(":method", "").
		Set(":authority", "").
		Set(":scheme", "").
		Set(":path", "").
		Set("pragma", "no-cache").
		Set("cache-control", "no-cache").
		Set("sec-ch-ua", `"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"`).
		Set("sec-ch-ua-mobile", "?0").
		Set("sec-ch-ua-platform", `"macOS"`).
		Set("upgrade-insecure-requests", "1").
		Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36").
		Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").
		Set("sec-fetch-site", "none").
		Set("sec-fetch-mode", "navigate").
		Set("sec-fetch-user", "?1").
		Set("sec-fetch-dest", "document").
		Set("referer", "").
		Set("accept-encoding", "gzip, deflate, br").
		Set("accept-language", "en-US,en;q=0.9").
		Set("cookie", "")

	return im.setOptions(headers)
}

// Firefox impersonates Firefox browser v.105.
func (im *impersonate) FireFox() *Options {
	priorityFrames := []http2.PriorityFrame{
		{
			FrameHeader: http2.FrameHeader{StreamID: 3},
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			},
		},
		{
			FrameHeader: http2.FrameHeader{StreamID: 5},
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			},
		},
		{
			FrameHeader: http2.FrameHeader{StreamID: 7},
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			},
		},
		{
			FrameHeader: http2.FrameHeader{StreamID: 9},
			PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			},
		},
		{
			FrameHeader: http2.FrameHeader{StreamID: 11},
			PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			},
		},
		{
			FrameHeader: http2.FrameHeader{StreamID: 13},
			PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			},
		},
	}

	// "akamai_fingerprint": "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
	im.opt.JA3().Firefox().
		HTTP2Settings().
		HeaderTableSize(65536).
		InitialWindowSize(131072).
		MaxFrameSize(16384).
		ConnectionFlow(12517377).
		PriorityParam(
			http2.PriorityParam{
				StreamDep: 13,
				Exclusive: false,
				Weight:    41,
			}).
		PriorityFrames(priorityFrames).
		Set()

	headers := g.NewMapOrd[string, string]().
		Set(":method", "").
		Set(":path", "").
		Set(":authority", "").
		Set(":scheme", "").
		Set("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0").
		Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8").
		Set("accept-language", "en-US,en;q=0.9").
		Set("accept-encoding", "gzip, deflate, br").
		Set("referer", "").
		Set("cookie", "").
		Set("upgrade-insecure-requests", "1").
		Set("sec-fetch-dest", "document").
		Set("sec-fetch-mode", "navigate").
		Set("sec-fetch-site", "none").
		Set("sec-fetch-user", "?1").
		Set("te", "Trailers")

	return im.setOptions(headers)
}

func (im *impersonate) setOptions(headers *g.MapOrd[string, string]) *Options {
	return im.opt.addreqMW(func(r *Request) error {
		r.SetHeaders(headers)
		return nil
	})
}
