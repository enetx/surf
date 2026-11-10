# Outgoing dynamic QPACK

The existing QUIC fork now owns an isolated RFC 9204 encoder, reusing the official
QPACK static table and x/net Huffman codec. No additional QPACK/uTLS fork is used.
Browser policies live in Surf's fluent `profiles/*/quic/qpack.go` functions.

Chromium uses insertion with available static/dynamic name references, Huffman
only when strictly shorter, a quarter-table draining reservation and Base equal
to Required Insert Count. Firefox inserts new names with literal-name instructions,
uses Huffman for literal strings, fixes Base before the section and stops trying
new insertions after the first failure. Ordered fields and cookie handling are
preserved. Configured encoder capacity is capped by the peer's limit; both browser
captures choose 65536 when the peer offers 65536, rather than the 4096 incorrectly
reported in the earlier historical notes.

Sources:
[Chromium encoder](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/qpack/qpack_encoder.cc),
[Chromium string encoding](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/qpack/qpack_instruction_encoder.cc),
[Firefox encoder](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-qpack/src/encoder.rs),
[Firefox field sections](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-qpack/src/header_block.rs).

## Independent verification

The QUIC module's `tests/qpack/testdata/browser/` preserves generic protocol vectors
extracted from the original independent browser fixtures, with source hashes.
`TestEncoderIndependentBrowserVectors` checks all 88 original field sections and
the complete encoder instructions at peer capacities 0, 128, 4096 and 65536.
SETTINGS event positions and sequential section acknowledgments are explicit.
These expectations are browser bytes, not snapshots produced by the new encoder.

`browser_observations.json` records fresh local packet captures with real Chromium
156 and Firefox 159, plus Surf's identical-input replay. With aligned initial
SETTINGS history, all 88 field sections and all eight concatenated encoder streams
match byte for byte. Stream IDs, source hashes, browser versions and pcap hashes
are retained. A matching encoder stream is a byte-stream result, not a claim of
identical QUIC packet boundaries or transmission timing.

The report also retains two differing Firefox repeats: Surf's first request was
static while the browser's first request used the dynamic table. Later field
values were identical, but their compression histories differed. Neither side
must wait for peer SETTINGS before sending its first request. We do not add such
a wait or discard these observations. Repeating those capacities with aligned
initial state produced the exact results recorded in the main matrix.

Wireshark does not independently decode every dynamic field section in these
captures; the report retains decoded/undecoded counts. The comparison uses actual
reassembled raw section bytes and encoder instructions. The receiving HTTP/3 peer
also checks decoded ordered fields. Raw pcap files, TLS keys and isolated browser
profiles remain private temporary artifacts. Firefox needed its content sandbox
disabled for the temporary local headless process; this did not change personal
profiles or persistent browser settings.

Reproduce with the [capture tool](../../../tools/wirecapture/README.md), then run
`analyze.mjs`. Always use a fresh capture directory. The offline regression and
local HTTP/3 tests require no browser, Wireshark or public endpoint.

## Regression coverage

QUIC's `tests/qpack/` covers native static compatibility, raw wire vectors, both
Base forms, Huffman and never-index fields, eviction/RIC wrapping, duplicate
instructions, blocking/tracking limits, FIFO ACKs and cancellation, fragmented
or invalid feedback, atomic backpressure fallback and concurrent access. Fuzzing
checks encoding/decoding and malformed decoder instructions.

`tests/http3/qpack_encoder_test.go` covers real client/server exchanges, repeated
requests, sorted fields, concurrent bodies/trailers, zero-capacity fallback,
exhausted encoder-stream credit and connection errors. Private HTTP/3 tests verify
sorted trailer announcements,
trailer fields and rejection before state changes. Surf tests verify fluent
options, validation, client snapshots across origins, raw strings, zero capacity
and exact zero-capacity browser blocks for both profiles.
