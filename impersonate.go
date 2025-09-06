package surf

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/enetx/g"
	"github.com/enetx/http2"
	"github.com/enetx/surf/header"
)

type Impersonate struct {
	builder *Builder
	os      ImpersonateOS
}

// RandomOS selects a random OS (Windows, macOS, Linux, Android, or iOS) for the impersonate.
func (im *Impersonate) RandomOS() *Impersonate {
	im.os = g.SliceOf(windows, macos, linux, android, ios).Random()
	return im
}

// Windows sets the OS to Windows.
func (im *Impersonate) Windows() *Impersonate {
	im.os = windows
	return im
}

// MacOS sets the OS to macOS.
func (im *Impersonate) MacOS() *Impersonate {
	im.os = macos
	return im
}

// Linux sets the OS to Linux.
func (im *Impersonate) Linux() *Impersonate {
	im.os = linux
	return im
}

// Android sets the OS to Android.
func (im *Impersonate) Android() *Impersonate {
	im.os = android
	return im
}

// IOS sets the OS to iOS.
func (im *Impersonate) IOS() *Impersonate {
	im.os = ios
	return im
}

// Chrome impersonates Chrome browser v.131.
func (im *Impersonate) Chrome() *Builder {
	// Set current browser type for automatic HTTP/3 detection
	im.builder.browser = chrome

	// "ja3_hash": random,
	// "ja4": "t13d1516h2_8daaf6152771_923f26044972",
	// "peetprint_hash": "7466733991096b3f4e6c0e79b0083559",
	// "akamai_fingerprint_hash": "52d84b11737d980aef856699f885ca86",

	im.builder.
		// Blink implementation: https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/platform/network/form_data_encoder.cc;drc=1d694679493c7b2f7b9df00e967b4f8699321093;l=130
		// WebKit implementation: https://github.com/WebKit/WebKit/blob/main/Source/WebCore/platform/network/FormDataBuilder.cpp#L120
		Boundary(func() g.String {
			// C++
			// Vector<uint8_t> generateUniqueBoundaryString()
			// {
			//     Vector<uint8_t> boundary;
			//
			//     // The RFC 2046 spec says the alphanumeric characters plus the
			//     // following characters are legal for boundaries:  '()+_,-./:=?
			//     // However the following characters, though legal, cause some sites
			//     // to fail: (),./:=+
			//     // Note that our algorithm makes it twice as much likely for 'A' or 'B'
			//     // to appear in the boundary string, because 0x41 and 0x42 are present in
			//     // the below array twice.
			//     static constexpr std::array<char, 64> alphaNumericEncodingMap {
			//         0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			//         0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
			//         0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
			//         0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
			//         0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
			//         0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
			//         0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
			//         0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42
			//     };
			//
			//     // Start with an informative prefix.
			//     append(boundary, "----WebKitFormBoundary");
			//
			//     // Append 16 random 7-bit ASCII alphanumeric characters.
			//     for (unsigned i = 0; i < 4; ++i) {
			//         unsigned randomness = cryptographicallyRandomNumber<unsigned>();
			//         boundary.append(alphaNumericEncodingMap[(randomness >> 24) & 0x3F]);
			//         boundary.append(alphaNumericEncodingMap[(randomness >> 16) & 0x3F]);
			//         boundary.append(alphaNumericEncodingMap[(randomness >> 8) & 0x3F]);
			//         boundary.append(alphaNumericEncodingMap[randomness & 0x3F]);
			//     }
			//
			//     return boundary;
			// }

			prefix := "----WebKitFormBoundary"

			alphaNumericEncodingMap := []byte{
				0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
				0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
				0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
				0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
				0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
				0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
				0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
				0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42,
			}

			boundary := []byte(prefix)

			for range 4 {
				randomBytes := make([]byte, 4)
				rand.Read(randomBytes)

				randomness := uint32(randomBytes[0])<<24 |
					uint32(randomBytes[1])<<16 |
					uint32(randomBytes[2])<<8 |
					uint32(randomBytes[3])

				boundary = append(boundary, alphaNumericEncodingMap[(randomness>>24)&0x3F])
				boundary = append(boundary, alphaNumericEncodingMap[(randomness>>16)&0x3F])
				boundary = append(boundary, alphaNumericEncodingMap[(randomness>>8)&0x3F])
				boundary = append(boundary, alphaNumericEncodingMap[randomness&0x3F])
			}

			return g.String(boundary)
		}).
		JA().Chrome131().
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
	//   "sec-ch-ua: \\\"Google Chrome\\\";v=\\\"131\\\", \\\"Chromium\\\";v=\\\"131\\\", \\\"Not_A Brand\\\";v=\\\"24\\",
	//   "sec-ch-ua-mobile: ?0",
	//   "sec-ch-ua-platform: \\\"Windows\\",
	//   "upgrade-insecure-requests: 1",
	//   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	//   "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	//   "sec-fetch-site: none",
	//   "sec-fetch-mode: navigate",
	//   "sec-fetch-user: ?1",
	//   "sec-fetch-dest: document",
	//   "accept-encoding: gzip, deflate, br, zstd",
	//   "accept-language: en-US,en;q=0.9",
	//   "priority: u=0, i"
	// ],

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.SEC_CH_UA, chromeSecCHUA)
	headers.Set(header.SEC_CH_UA_MOBILE, im.os.mobile())
	headers.Set(header.SEC_CH_UA_PLATFORM, chromePlatform[im.os])
	headers.Set(header.UPGRADE_INSECURE_REQUESTS, "1")
	headers.Set(header.USER_AGENT, chromeUserAgent[im.os])
	headers.Set(
		header.ACCEPT,
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	)
	headers.Set(header.SEC_FETCH_SITE, "none")
	headers.Set(header.SEC_FETCH_MODE, "navigate")
	headers.Set(header.SEC_FETCH_USER, "?1")
	headers.Set(header.SEC_FETCH_DEST, "document")
	headers.Set(header.REFERER, "")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.9")
	headers.Set(header.PRIORITY, "u=0, i")

	return im.setHeaders(headers)
}

// Firefox impersonates Firefox browser v.131.
func (im *Impersonate) FireFox() *Builder {
	// Set current browser type for automatic HTTP/3 detection
	im.builder.browser = firefox

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

	// "ja3_hash": "b5001237acdf006056b409cc433726b0",
	// "ja4": "t13d1715h2_5b57614c22b0_2764158f9823",
	// "peetprint_hash": "b9c611f928c8c1f20c414a48c66abf27",
	// "akamai_fingerprint_hash": "3d9132023bf26a71d40fe766e5c24c9d",

	im.builder.
		// Firefox implementation: https://github.com/mozilla/gecko-dev/blob/master/dom/html/HTMLFormSubmission.cpp#L355
		Boundary(func() g.String {
			// C++
			// mBoundary.AssignLiteral("----geckoformboundary");
			// mBoundary.AppendInt(mozilla::RandomUint64OrDie(), 16);
			// mBoundary.AppendInt(mozilla::RandomUint64OrDie(), 16);

			// prefix := "----geckoformboundary"
			// var num1, num2 uint64
			// binary.Read(rand.Reader, binary.BigEndian, &num1)
			// binary.Read(rand.Reader, binary.BigEndian, &num2)
			// return g.Sprintf("%s%x%x", prefix, num1, num2)

			////////////////////////////////////////////////////////////////////////////

			// C++
			// mBoundary.AssignLiteral("---------------------------");
			// mBoundary.AppendInt(static_cast<uint32_t>(mozilla::RandomUint64OrDie()));
			// mBoundary.AppendInt(static_cast<uint32_t>(mozilla::RandomUint64OrDie()));
			// mBoundary.AppendInt(static_cast<uint32_t>(mozilla::RandomUint64OrDie()));

			prefix := g.String("---------------------------")

			var builder g.Builder
			builder.WriteString(prefix)

			for range 3 {
				var b [4]byte
				rand.Read(b[:])
				builder.WriteString(g.Int(binary.LittleEndian.Uint32(b[:])).String())
			}

			return builder.String()
		}).
		JA().Firefox131().
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
	//   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
	//   "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
	//   "accept-language: en-US,en;q=0.5",
	//   "accept-encoding: gzip, deflate, br, zstd",
	//   "upgrade-insecure-requests: 1",
	//   "sec-fetch-dest: document",
	//   "sec-fetch-mode: navigate",
	//   "sec-fetch-site: none",
	//   "sec-fetch-user: ?1",
	//   "priority: u=0, i"
	// ],

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":path", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.USER_AGENT, firefoxUserAgent[im.os])
	headers.Set(
		header.ACCEPT,
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
	)
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.REFERER, "")
	headers.Set(header.UPGRADE_INSECURE_REQUESTS, "1")
	headers.Set(header.SEC_FETCH_DEST, "document")
	headers.Set(header.SEC_FETCH_MODE, "navigate")
	headers.Set(header.SEC_FETCH_SITE, "none")
	headers.Set(header.SEC_FETCH_USER, "?1")
	headers.Set(header.PRIORITY, "u=0, i")
	// headers.Set(header.TE, "trailers")

	return im.setHeaders(headers)
}

func (im *Impersonate) setHeaders(headers g.MapOrd[g.String, g.String]) *Builder {
	return im.builder.SetHeaders(headers)
}
