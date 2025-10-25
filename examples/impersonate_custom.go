package main

import (
	"log"

	"github.com/enetx/g"
	"github.com/enetx/http2"
	"github.com/enetx/surf"
)

func main() {
	headers := g.NewMapOrd[g.String, g.String]()

	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("sec-ch-ua", "\"Google Chrome\";v=\"87\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"87\"")
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("sec-ch-ua-platform", "\"Windows\"")
	headers.Set("Upgrade-Insecure-Requests", "1")
	headers.Set(
		"Accept",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
	)
	headers.Set("Sec-Fetch-Site", "none")
	headers.Set("Sec-Fetch-Mode", "navigate")
	headers.Set("Sec-Fetch-User", "?1")
	headers.Set("Sec-Fetch-Dest", "document")
	headers.Set("Accept-Encoding", "gzip, deflate, br")
	headers.Set("User-Agent", "")
	headers.Set("Accept-Language", "en-US,en;q=0.9")

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

	b := g.NewBuilder()
	b.WriteString("-------SurfFormBoundary")
	b.WriteString(g.ASCII_LETTERS.Random(7))

	cli := surf.NewClient().
		Builder().
		Boundary(b.String).
		JA().Chrome87().
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
		With(func(req *surf.Request) error {
			req.SetHeaders(headers)
			return nil
		}).
		Build()

	const url = "https://tls.peet.ws/api/all"

	r := cli.Get(url).Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	r.Ok().Debug().Request(true).Response(true).Print()
}
