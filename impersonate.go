package surf

import (
	"github.com/enetx/g"
	"github.com/enetx/http2"
	"github.com/enetx/surf/header"
	"github.com/enetx/surf/profiles/chrome"
	"github.com/enetx/surf/profiles/firefox"
)

type Impersonate struct {
	builder *Builder
	os      ImpersonateOS
}

// RandomOS selects a random OS (Windows, macOS, Linux, Android, or iOS) for the impersonate.
func (im *Impersonate) RandomOS() *Impersonate {
	im.os = g.SliceOf(windows, macos, android, ios).Random()
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

// Chrome impersonates Chrome browser v142.
func (im *Impersonate) Chrome() *Builder {
	im.builder.browser = chromeBrowser

	// "ja3": "random",
	// "ja3_hash": "random",
	// "ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
	// "ja4_r": "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601",
	// "akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
	// "akamai_hash": "52d84b11737d980aef856699f885ca86",
	// "peetprint": "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE",
	// "peetprint_hash": "1d4ffe9b0e34acac0bd883fa7f79d7b5"

	im.builder.
		Boundary(chrome.Boundary).
		JA().Chrome142().
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
			}).
		Set()

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":authority", "")
	headers.Set(":method", "")
	headers.Set(":path", "")
	headers.Set(":scheme", "")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.9")
	headers.Set(header.AUTHORIZATION, "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.ORIGIN, "")
	headers.Set(header.REFERER, "")
	headers.Set(header.SEC_CH_UA, chromeSecCHUA)
	headers.Set(header.SEC_CH_UA_MOBILE, im.os.mobile())
	headers.Set(header.SEC_CH_UA_PLATFORM, chromePlatform[im.os])
	headers.Set(header.USER_AGENT, chromeUserAgent[im.os])

	return im.builder.SetHeaders(headers)
}

// ChromeUB impersonates Chrome browser v142 ub.
func (im *Impersonate) ChromeUB() *Builder {
	im.builder.browser = chromeBrowserUB

	// "ja3": "random",
	// "ja3_hash": "random",
	// "ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
	// "ja4_r": "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601",
	// "akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
	// "akamai_hash": "52d84b11737d980aef856699f885ca86",
	// "peetprint": "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE",
	// "peetprint_hash": "1d4ffe9b0e34acac0bd883fa7f79d7b5"

	im.builder.
		Boundary(chrome.Boundary).
		JA().Chrome142().
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
			}).
		Set()

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":authority", "")
	headers.Set(":method", "")
	headers.Set(":path", "")
	headers.Set(":scheme", "")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.9")
	headers.Set(header.AUTHORIZATION, "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.ORIGIN, "")
	headers.Set(header.REFERER, "")
	headers.Set(header.SEC_CH_UA, chromeSecCHUA)
	headers.Set(header.SEC_CH_UA_MOBILE, im.os.mobile())
	headers.Set(header.SEC_CH_UA_PLATFORM, chromePlatform[im.os])
	headers.Set(header.USER_AGENT, chromeUserAgent[im.os])

	return im.builder.SetHeaders(headers)
}

// FireFox impersonates Firefox browser v144.
func (im *Impersonate) FireFox() *Builder {
	im.builder.browser = firefoxBrowser

	// "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0",
	// "ja3_hash": "6f7889b9fb1a62a9577e685c1fcfa919",
	// "ja4": "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
	// "ja4_r": "t13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
	// "akamai": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
	// "akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
	// "peetprint": "772-771|2-1.1|4588-29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|1|1-2-3|4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53|0-10-11-13-16-18-23-27-28-34-35-43-45-5-51-65037-65281",
	// "peetprint_hash": "89d89662b21018947a9a46658c4f5ede"

	im.builder.
		Boundary(firefox.Boundary).
		JA().Firefox144().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(0).
		InitialWindowSize(131072).
		MaxFrameSize(16384).
		ConnectionFlow(12517377).
		PriorityParam(
			http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    41,
			}).
		Set()

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":authority", "")
	headers.Set(":method", "")
	headers.Set(":path", "")
	headers.Set(":scheme", "")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5")
	headers.Set(header.AUTHORIZATION, "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.ORIGIN, "")
	headers.Set(header.REFERER, "")
	headers.Set(header.USER_AGENT, firefoxUserAgent[im.os])

	return im.builder.SetHeaders(headers)
}

// FireFoxUB impersonates Firefox browser v144 ub.
func (im *Impersonate) FireFoxUB() *Builder {
	im.builder.browser = firefoxBrowserUB

	// "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0",
	// "ja3_hash": "6f7889b9fb1a62a9577e685c1fcfa919",
	// "ja4": "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
	// "ja4_r": "t13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
	// "akamai": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
	// "akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
	// "peetprint": "772-771|2-1.1|4588-29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|1|1-2-3|4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53|0-10-11-13-16-18-23-27-28-34-35-43-45-5-51-65037-65281",
	// "peetprint_hash": "89d89662b21018947a9a46658c4f5ede"

	im.builder.
		Boundary(firefox.Boundary).
		JA().Firefox144().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(0).
		InitialWindowSize(131072).
		MaxFrameSize(16384).
		ConnectionFlow(12517377).
		PriorityParam(
			http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    41,
			}).
		Set()

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":authority", "")
	headers.Set(":method", "")
	headers.Set(":path", "")
	headers.Set(":scheme", "")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5")
	headers.Set(header.AUTHORIZATION, "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.ORIGIN, "")
	headers.Set(header.REFERER, "")
	headers.Set(header.USER_AGENT, firefoxUserAgent[im.os])

	return im.builder.SetHeaders(headers)
}

// FireFoxPrivate impersonates Firefox private browser v144.
func (im *Impersonate) FireFoxPrivate() *Builder {
	im.builder.browser = firefoxBrowser

	// "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-28-27-65037,4588-29-23-24-25-256-257,0",
	// "ja3_hash": "7704a11cf87dfcf33080b90ce11d5527",
	// "ja4": "t13d1715h2_5b57614c22b0_a54fffd0eb61",
	// "ja4_r": "t13d1715h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,002b,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
	// "akamai": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
	// "akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
	// "peetprint": "772-771|2-1.1|4588-29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|0|1-2-3|4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53|0-10-11-13-16-18-23-27-28-34-43-5-51-65037-65281",
	// "peetprint_hash": "d5b32f4cbc2381b4c0548aa52f5a6606"

	im.builder.
		Boundary(firefox.Boundary).
		JA().FirefoxPrivate144().
		HTTP2Settings().
		HeaderTableSize(65536).
		EnablePush(0).
		InitialWindowSize(131072).
		MaxFrameSize(16384).
		ConnectionFlow(12517377).
		PriorityParam(
			http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    41,
			}).
		Set()

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":authority", "")
	headers.Set(":method", "")
	headers.Set(":path", "")
	headers.Set(":scheme", "")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5")
	headers.Set(header.AUTHORIZATION, "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.ORIGIN, "")
	headers.Set(header.REFERER, "")
	headers.Set(header.USER_AGENT, firefoxUserAgent[im.os])

	return im.builder.SetHeaders(headers)
}

// Tor impersonates Tor browser v14.5.6.
func (im *Impersonate) Tor() *Builder {
	im.builder.browser = firefoxBrowser

	// "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
	// "ja3_hash": "9a7f6a45c84d90c9e8baecb0c9ae8dff",
	// "ja4": "t13d1515h2_8daaf6152771_2764158f9823",
	// "ja4_r": "t13d1515h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0000,0005,000a,000b,000d,0017,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
	// "akamai": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
	// "akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
	// "peetprint": "772-771|2-1.1|29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|1||4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53|0-10-11-13-16-23-28-34-35-43-45-5-51-65037-65281",
	// "peetprint_hash": "2eb215311454f1bcef8d33d5281a880d"

	im.builder.
		Boundary(firefox.Boundary).
		JA().Tor().
		HTTP2Settings().
		HeaderTableSize(65536).
		InitialWindowSize(131072).
		MaxFrameSize(16384).
		EnablePush(0).
		ConnectionFlow(12517377).
		PriorityParam(
			http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    41,
			}).
		Set()

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":authority", "")
	headers.Set(":method", "")
	headers.Set(":path", "")
	headers.Set(":scheme", "")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5")
	headers.Set(header.AUTHORIZATION, "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.ORIGIN, "")
	headers.Set(header.REFERER, "")
	headers.Set(header.USER_AGENT, torUserAgent[im.os])

	return im.builder.SetHeaders(headers)
}

// TorPrivate impersonates Tor private browser v14.5.6.
func (im *Impersonate) TorPrivate() *Builder {
	im.builder.browser = firefoxBrowser

	// "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-65037,29-23-24-25-256-257,0",
	// "ja3_hash": "0faf2a91198d40dbd58b9308f3fca2fd",
	// "ja4": "t13d1513h2_8daaf6152771_b10d063d83a8",
	// "ja4_r": "t13d1513h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0000,0005,000a,000b,000d,0017,001c,0022,002b,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
	// "akamai": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
	// "akamai_hash": "6ea73faa8fc5aac76bded7bd238f6433",
	// "peetprint": "772-771|2-1.1|29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|0||4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53|0-10-11-13-16-23-28-34-43-5-51-65037-65281",
	// "peetprint_hash": "3838f472ba00b12aab5a866552abf7a4"

	im.builder.
		Boundary(firefox.Boundary).
		JA().TorPrivate().
		HTTP2Settings().
		HeaderTableSize(65536).
		InitialWindowSize(131072).
		MaxFrameSize(16384).
		EnablePush(0).
		ConnectionFlow(12517377).
		PriorityParam(
			http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    41,
			}).
		Set()

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":authority", "")
	headers.Set(":method", "")
	headers.Set(":path", "")
	headers.Set(":scheme", "")
	headers.Set(header.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
	headers.Set(header.ACCEPT_LANGUAGE, "en-US,en;q=0.5")
	headers.Set(header.AUTHORIZATION, "")
	headers.Set(header.COOKIE, "")
	headers.Set(header.ORIGIN, "")
	headers.Set(header.REFERER, "")
	headers.Set(header.USER_AGENT, torUserAgent[im.os])

	return im.builder.SetHeaders(headers)
}
