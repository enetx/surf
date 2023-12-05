package main

import (
	"log"

	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http2"
	"gitlab.com/x0xO/surf"
)

func main() {
	url := "https://tls.peet.ws/api/all"

	opt := surf.NewOptions()
	opt.JA3().Firefox()

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
	opt.HTTP2Settings().
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
		Set("cookie", "").
		Set("upgrade-insecure-requests", "1").
		Set("sec-fetch-dest", "document").
		Set("sec-fetch-mode", "navigate").
		Set("sec-fetch-site", "none").
		Set("sec-fetch-user", "?1").
		Set("te", "Trailers")

	r, err := surf.NewClient().SetOptions(opt).Get(url).
		SetHeaders(headers).
		Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Body.String().Print()
}
