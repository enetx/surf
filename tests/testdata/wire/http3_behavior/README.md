# HTTP/3 request bodies, priorities and early data

No new dependency forks were added. The QUIC fork exposes generic body/frame and
priority controls; browser policies live in Surf's fluent profiles. Captures use
the matching QUIC workspace code; release checks run against published modules
with the workspace disabled.

## Actual browser observations

`browser_observations.json` contains eight isolated Chromium 156.0.8078.79 /
Firefox 159.0.1 captures at peer QPACK capacities 0 and 65536. Both request bodies
and priorities were repeated. Every DATA length and PRIORITY_UPDATE value was
independently checked against decrypted Wireshark frames, attributed by the
connection's original destination ID. Capture hashes and observed reconnections
are retained. The separate HTTP/3 capture tool uses disposable browser profiles;
Firefox's sandbox override applied only to these temporary headless processes.

Chrome's nine upload sizes produce exactly the same DATA boundaries in Surf,
including the 371712-byte buffer ceiling. Firefox matches six small-body cases.
For three larger bodies, Surf uses the correct 32768-byte segment size while
Firefox's first DATA frame is shorter: Necko parses serialized request headers
from the same input segment before passing its remaining bytes to Neqo. This
first-boundary difference remains explicit in the report. No guessed fixed
header subtraction, packet timing or congestion policy is added.

Changing a visible image's `fetchPriority` during its response emitted no new
priority updates in either browser in this experiment. Chromium's initial
updates and Firefox's lack of them were observed. Surf's exact-input replay also
exercises explicit manual updates, including deduplication. Those additional
frames demonstrate the API; they are not an observed browser resource scheduler.

## Source references

- [Chromium upload buffer bounds](https://github.com/chromium/chromium/blob/156.0.8078.79/net/quic/quic_http_stream.cc)
  and [QUICHE packet-size constant](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_constants.h):
  clamp body length to 10–256 times 1452. Unknown-length bodies use the minimum.
- [Firefox HTTP/3 segment reader and header consumption](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/Http3Stream.cpp),
  [transaction input streams](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp),
  [segment preference application](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/netwerk/base/nsIOService.cpp)
  and [shipped 32768-byte preference](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/modules/libpref/init/all.js).
  The C++ static initializer of 4096 is overridden by the shipped preference.
- [Chromium priority updates](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/http/quic_spdy_stream.cc)
  and [priority serialization](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_stream_priority.cc).
- [Firefox priority state and serialization](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_159_0_1_RELEASE/third_party/rust/neqo-http3/src/priority.rs):
  no initial change, repeated values suppressed, `u=N,i` without a space.

## TLS 0-RTT scope

`EarlyData(true)` supports bodyless GET/HEAD with standard TLS and an explicit
session cache. It is disabled by default. Tests observe request-stream bytes in
actual 0-RTT packets, rejection, 425 retries using 1-RTT, normal and zero-length
connection IDs, SOCKS5 relay, cancellation before sending, GET with a body / POST
exclusion, HTTP/2 fallback and preservation of the caller's method/headers.

A direct probe with both official-uTLS browser templates resumed TLS but sent no
0-RTT request data. The current adapter therefore rejects `EarlyData(true)` with
custom ClientHello templates at build time. Ordinary Chrome/Firefox TLS session
resumption remains tested and supported. No private-layout casts, TLS handshake
patches, or new TLS fork were introduced to bypass this limitation.
The adapter uses [official uTLS QUIC](https://github.com/refraction-networking/utls/blob/a13c59ffe98b/u_quic.go)
and its [custom ClientHello/session handling](https://github.com/refraction-networking/utls/blob/a13c59ffe98b/u_conn.go).
This is not a claim of browser 0-RTT fingerprint parity.

## Regression coverage

Surf tests cover fluent settings and snapshots, profile overrides, captured Chrome
upload vectors, the Firefox segment size, concurrent updates, queue deduplication,
closed/canceled requests, reconnecting to the same origin with capacities
4096 → 0 → 65536, graceful GOAWAY and fresh QPACK state. QUIC tests additionally
exercise DATA-header/payload deadlines at every byte boundary, atomic
`TryWriteAll` retries, unknown body lengths and deterministic control backpressure.

Use the [capture tool](../../../tools/wirecapture/README.md) with `uploads` and
`priorities` scenarios, then `behavior-analysis.mjs`. Private pcaps, session keys,
certificates and browser profiles stay outside Git. Frame comparisons do not
establish matching QUIC packet boundaries, pacing, loss or congestion behavior.
