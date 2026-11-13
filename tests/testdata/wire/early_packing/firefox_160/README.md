# Firefox 160 accepted early GET capture

Native Firefox **does send a GET in accepted HTTP/3 0-RTT** in the recorded
ordinary opaque-fetch scenario. This closes the earlier missing native evidence
for early GET acceptance. It does not establish combined ECH+early-GET acceptance
or identical Surf packet scheduling.

The reference is the official Mozilla Firefox 160.0 Linux arm64 release, build
20261104181552, checked against Mozilla's published SHA-512. It ran visibly under
Xvfb, with certificate validation enabled and default browser DNS policy. BiDi,
NSS key logging and passive qlog observation were enabled. No HTTP/3, TLS,
early-data, certificate, proxy, IP-family or User-Agent override was used.

One about:blank context performed ordinary no-cors, credentials-omitted GETs to
Google's generate_204 endpoint: four warm requests, then three repeats separated
by 45 seconds of natural idle expiry. Opaque API completion was not treated as
protocol or acceptance proof.

| Native connection | Early request | TLS acceptance | Finished checks | HTTP response |
| --- | --- | --- | --- | --- |
| 3 | GET on stream 0, 141 request bytes, dynamic QPACK encoder stream 68 bytes | PSK identity 0; server early_data extension | Client and server independently verified | HTTP/3 204 on stream 0 |
| 6 | GET on stream 0, 141 request bytes, dynamic QPACK encoder stream 68 bytes | PSK identity 0; server early_data extension | Client and server independently verified | Later status not independently decoded; no second HTTP success claim |

Both connections contain two decrypted 0-RTT packets. One carries request and
control data; these are observations for these inputs, not a fixed packet count.
The original stream bytes were independently decoded using official
[pylsqpack](https://github.com/aiortc/pylsqpack) 1.1.1, including dynamic encoder
instructions. Both decoded methods are GET and both authorities are www.google.com.
Their ordered fields and stream hashes are retained in observations.json.

Acceptance is established from selected PSK identity 0, the server's
EncryptedExtensions early_data extension, and independent HMAC checks of both
TLS Finished messages against the original transcript and logged handshake
secrets, following [RFC 8446 section 4.4.4](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.4).
The native browser itself also validated the certificate and handshake.
Google's recorded resumptions do not use real ECH.

A separate Cloudflare navigation capture authenticates accepted ECH, selected
PSK and two accepted control-only early packets. Its redacted, offline-verified
reference is [firefox-160-quic-2.json](../../ech/resumption/native/firefox-160-quic-2.json).
Other navigation/fetch attempts legitimately selected HTTP/2 or did not send the
GET early. The capture does not imply early GET on every Firefox request.

## Capture completeness

The Google pcap contains **21,180 captured/filter packets, zero kernel drops and
zero truncated frames**. The Cloudflare reference contains **15,620 packets**,
also complete and without kernel drops. Original capture hashes are recorded in
observations.json. Keys, tickets, complete pcaps, browser profiles and raw
handshakes remain private.

Earlier Linux immediate-mode samples were excluded: offload superpackets could
have frame.cap_len smaller than frame.len despite a large requested snap length
and zero reported drops. Buffered capture and disabled UDP segmentation offload
removed that truncation. The extractor now rejects such incomplete frame JSON;
its regression uses the observed 2546/1530-byte truncation.

## Reproduction

Start a full tcpdump capture in the browser's network namespace before launching
Firefox; allow it to drain and stop with SIGINT afterward. Check every raw frame's
captured/original length before filtering or decoding. For this sequence:

```sh
SURF_CAPTURE_DNS=default SURF_CAPTURE_QLOG=1 \
SURF_CAPTURE_URL=https://www.google.com/generate_204 \
node tests/tools/echresumption/native.mjs firefox /private/NEW_DIR \
    /path/to/official/firefox h3 no-cors-fetch
```

Use the resulting NSS key log with TShark and retain all packets of each QUIC
connection. A fresh profile, external server policy, path loss and protocol-race
outcomes can change which repeats resume. Never infer acceptance from the
requested scenario or from opaque status 0.

[Http3Session](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http3Session.cpp)
admits 0-RTT streams through
[Http3Stream::Do0RTT](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http3Stream.cpp),
which delegates safe-method eligibility to
[nsHttpTransaction](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp).
These sources permit early GET; the capture establishes its occurrence and
server acceptance in the retained scenario, rather than inferring it from code.
