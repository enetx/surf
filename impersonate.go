package surf

import (
	"github.com/enetx/g"
	"github.com/enetx/http2"
	"github.com/enetx/surf/header"
)

type impersonate struct{ builder *builder }

// Chrome impersonates Chrome browser v.123.
func (im *impersonate) Chrome() *builder {
	// "ja3_hash": random,
	// "ja4": "t13d1516h2_8daaf6152771_b1ff8ab2d16f",
	// "peetprint_hash": "8ad9325e12f531d2983b78860de7b0ec",
	// "akamai_fingerprint_hash": "90224459f8bf70b7d0a8797eb916dbc9",

	im.builder.JA3().Chrome().
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
	//   "sec-ch-ua: \\\"Google Chrome\\\";v=\\\"123\\\", \\\"Not:A-Brand\\\";v=\\\"8\\\", \\\"Chromium\\\";v=\\\"123\\",
	//   "sec-ch-ua-mobile: ?0",
	//   "sec-ch-ua-platform: \\\"Windows\\",
	//   "upgrade-insecure-requests: 1",
	//   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	//   "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	//   "sec-fetch-site: none",
	//   "sec-fetch-mode: navigate",
	//   "sec-fetch-user: ?1",
	//   "sec-fetch-dest: document",
	//   "accept-encoding: gzip, deflate, br, zstd",
	//   "accept-language: en-US,en;q=0.9"
	// ],

	headers := g.NewMapOrd[string, string]()
	headers.
		Set(":method", "").
		Set(":authority", "").
		Set(":scheme", "").
		Set(":path", "").
		Set(header.COOKIE, "").
		Set(header.SEC_CH_UA, `"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"`).
		Set(header.SEC_CH_UA_MOBILE, "?0").
		Set(header.SEC_CH_UA_PLATFORM, `"Windows"`).
		// Set(header.DNT, "1").
		Set(header.UPGRADE_INSECURE_REQUESTS, "1").
		Set(header.USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36").
		Set(header.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7").
		Set(header.SEC_FETCH_SITE, "none").
		Set(header.SEC_FETCH_MODE, "navigate").
		Set(header.SEC_FETCH_USER, "?1").
		Set(header.SEC_FETCH_DEST, "document").
		Set(header.REFERER, "").
		Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd").
		Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.9")

	return im.setOptions(headers)
}

// Firefox impersonates Firefox browser v.124.
func (im *impersonate) FireFox() *builder {
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

	im.builder.JA3().Firefox().
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
	//   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
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

	headers := g.NewMapOrd[string, string]()
	headers.
		Set(":method", "").
		Set(":path", "").
		Set(":authority", "").
		Set(":scheme", "").
		Set(header.COOKIE, "").
		Set(header.USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0").
		Set(header.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8").
		Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5").
		Set(header.ACCEPT_ENCODING, "gzip, deflate, br").
		Set(header.REFERER, "").
		Set(header.UPGRADE_INSECURE_REQUESTS, "1").
		Set(header.SEC_FETCH_DEST, "document").
		Set(header.SEC_FETCH_MODE, "navigate").
		Set(header.SEC_FETCH_SITE, "none").
		Set(header.SEC_FETCH_USER, "?1")
		// Set(header.TE, "trailers")

	return im.setOptions(headers)
}

func (im *impersonate) setOptions(headers g.MapOrd[string, string]) *builder {
	return im.builder.addReqMW(func(r *Request) error {
		r.SetHeaders(headers)
		return nil
	})
}
