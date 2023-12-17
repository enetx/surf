package surf

import (
	"gitlab.com/x0xO/g"
	"gitlab.com/x0xO/http2"
)

type impersonate struct{ opt *Options }

// Chrome impersonates Chrome browser v.120.
func (im *impersonate) Chrome120() *Options {
	// "ja3_hash": random,
	// "ja4": "t13d1516h2_8daaf6152771_b1ff8ab2d16f",
	// "peetprint_hash": "8ad9325e12f531d2983b78860de7b0ec",
	// "akamai_fingerprint_hash": "90224459f8bf70b7d0a8797eb916dbc9",

	im.opt.JA3().Chrome().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(0).
		InitialWindowSize(6291456).
		MaxHeaderListSize(262144).
		ConnectionFlow(15663105).
		PriorityParam(
			http2.PriorityParam{
				StreamDep: 0,
				Exclusive: true,
				Weight:    255,
			}).Set()

	// "headers": [
	//   ":method: GET",
	//   ":authority: tls.peet.ws",
	//   ":scheme: https",
	//   ":path: /api/all",
	//   "sec-ch-ua: \\\"Not_A Brand\\\";v=\\\"8\\\", \\\"Chromium\\\";v=\\\"120\\\", \\\"Google Chrome\\\";v=\\\"120\\",
	//   "sec-ch-ua-mobile: ?0",
	//   "sec-ch-ua-platform: \\\"Windows\\",
	//   "upgrade-insecure-requests: 1",
	//   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	//   "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	//   "sec-fetch-site: none",
	//   "sec-fetch-mode: navigate",
	//   "sec-fetch-user: ?1",
	//   "sec-fetch-dest: document",
	//   "accept-encoding: gzip, deflate, br",
	//   "accept-language: en-US,en;q=0.9"
	// ],

	headers := g.NewMapOrd[string, string]().
		Set(":method", "").
		Set(":authority", "").
		Set(":scheme", "").
		Set(":path", "").
		Set("sec-ch-ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`).
		Set("sec-ch-ua-mobile", "?0").
		Set("sec-ch-ua-platform", `"Windows"`).
		Set("upgrade-insecure-requests", "1").
		Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36").
		Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7").
		Set("sec-fetch-site", "none").
		Set("sec-fetch-mode", "navigate").
		Set("sec-fetch-user", "?1").
		Set("sec-fetch-dest", "document").
		Set("accept-encoding", "gzip, deflate, br").
		Set("accept-language", "en-US,en;q=0.9")

	return im.setOptions(headers)
}

// Firefox impersonates Firefox browser v.120.
func (im *impersonate) FireFox120() *Options {
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

	// "ja3_hash": "ed3d2cb3d86125377f5a4d48e431af48",
	// "ja4": "t13d1713h2_5b57614c22b0_0429eda30173",
	// "peetprint_hash": "618e6b31ed28ba8b6ecd19f29fc8de50",
	// "akamai_fingerprint_hash": "fd4f649c50a64e33cc9e2407055bafbe",

	im.opt.JA3().Firefox120().
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

	// "headers": [
	//   ":method: GET",
	//   ":path: /api/all",
	//   ":authority: tls.peet.ws",
	//   ":scheme: https",
	//   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	//   "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	//   "accept-language: en-US,en;q=0.5",
	//   "accept-encoding: gzip, deflate, br",
	//   "upgrade-insecure-requests: 1",
	//   "sec-fetch-dest: document",
	//   "sec-fetch-mode: navigate",
	//   "sec-fetch-site: none",
	//   "sec-fetch-user: ?1",
	//   "te: trailers"
	// ],

	headers := g.NewMapOrd[string, string]().
		Set(":method", "").
		Set(":path", "").
		Set(":authority", "").
		Set(":scheme", "").
		Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0").
		Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8").
		Set("accept-language", "en-US,en;q=0.5").
		Set("accept-encoding", "gzip, deflate, br").
		Set("upgrade-insecure-requests", "1").
		Set("sec-fetch-dest", "document").
		Set("sec-fetch-mode", "navigate").
		Set("sec-fetch-site", "none").
		Set("sec-fetch-user", "?1").
		Set("te", "trailers")

	return im.setOptions(headers)
}

func (im *impersonate) setOptions(headers *g.MapOrd[string, string]) *Options {
	return im.opt.addreqMW(func(r *Request) error {
		r.SetHeaders(headers)
		return nil
	})
}
