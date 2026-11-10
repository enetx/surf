package quic

import "github.com/enetx/surf/profiles"

// ConfigureRequestBody follows Http3Stream's ReadSegmentsAgain size, using
// network.buffer.cache.size preference (custom browser prefs can differ).
// The first DATA frame can be shorter because Necko reads serialized request
// headers and body from the same segment. This selects the segment size only.
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/Http3Stream.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/base/nsIOService.cpp
// https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/modules/libpref/init/all.js
func ConfigureRequestBody(h profiles.H3Config) {
	h.RequestBodyBufferSize(32768)
}
