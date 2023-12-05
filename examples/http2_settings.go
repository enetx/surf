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

	opt.HTTP2Settings().
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
		Set()

	opt.JA3().Chrome87()
	opt.ForceHTTP1()

	headers := g.NewMapOrd[string, string]().
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

	r, err := surf.NewClient().SetOptions(opt).Get(url).
		SetHeaders(headers).
		Do()
	if err != nil {
		log.Fatal(err)
	}

	r.Debug().Request(true).Response(true).Print()
}
