package main

import (
	"log"

	"github.com/enetx/g"
	"github.com/enetx/http2"
	"github.com/enetx/surf"
)

func main() {
	url := "https://tls.peet.ws/api/all"

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
	}

	cli := surf.NewClient().
		Builder().
		JA3().Chrome87().
		HTTP2Settings().
		EnablePush(1).
		MaxConcurrentStreams(1000).
		MaxFrameSize(16384).
		MaxHeaderListSize(262144).
		InitialWindowSize(6291456).
		HeaderTableSize(65536).
		PriorityParam(http2.PriorityParam{
			Exclusive: true,
			Weight:    255,
			StreamDep: 0,
		}).
		PriorityFrames(priorityFrames).
		Set().
		Build()

	headers := g.NewMapOrd[string, string]()
	headers.
		Set(":method", "").
		Set(":authority", "").
		Set(":scheme", "").
		Set(":path", "").
		Set("sec-ch-ua", "\"Google Chrome\";v=\"87\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"87\"").
		Set("sec-ch-ua-mobile", "?0").
		Set("sec-ch-ua-platform", "\"Windows\"").
		Set("Upgrade-Insecure-Requests", "1").
		Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").
		Set("Sec-Fetch-Site", "none").
		Set("Sec-Fetch-Mode", "navigate").
		Set("Sec-Fetch-User", "?1").
		Set("Sec-Fetch-Dest", "document").
		Set("Accept-Encoding", "gzip, deflate, br").
		Set("User-Agent", "").
		Set("Accept-Language", "en-US,en;q=0.9")

	r := cli.Get(url).SetHeaders(headers).Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Request(true).Response(true).Print()
}
