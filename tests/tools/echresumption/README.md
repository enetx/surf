# ECH resumption capture tools

Run from Surf's module root with Go 1.27+, Node 22+ and Wireshark/TShark 4.6.9+.
Public networking is opt-in and is not part of the deterministic CI suite.
Use official browser executables matching the reference version.

## Capture Surf through the fluent API

Start tcpdump before the probe and stop it with SIGINT, waiting for it to flush
before analysis. Keep the capture directory private (`umask 077`).

```sh
go run ./tests/tools/echresumption -probe chrome -protocol h3 -early -dns 1.1.1.1:53 -keylog /private/capture/chrome-h3.keys
go run ./tests/tools/echresumption -probe firefox -protocol h3 -early -keylog /private/capture/firefox-h3.keys
go run ./tests/tools/echresumption -probe firefox -protocol h3 -early -racing -keylog /private/capture/firefox-racing.keys
go run ./tests/tools/echresumption -probe chrome -protocol h2 -keylog /private/capture/chrome-h2.keys
```

The implementation in `probe.go` demonstrates ordinary `Impersonate`,
`ForceHTTP2`/`ForceHTTP3`, `HTTP3Settings().EarlyData(true).Set()`, `TLSConfig`,
`SecureTLS`, `Session`, and `CloseIdleConnections` calls. One shared client/session
cache makes three fresh connections. The probe fails on certificate/ECH failure
or failure to resume its repeated handshakes. It never overwrites a key log.
Early data is explicitly enabled only by `-early`; library defaults stay intact.
Optional `-dns HOST:PORT` selects the ordinary public Builder.DNS resolver.
Choose a resolver that supplies HTTPS/ECH records for the capture endpoint.
`-racing` enables the profile's TCP/QUIC preparation policy instead of forcing
HTTP/3. It requires `-protocol h3`. This probe still requires HTTP/3 on every
attempt, so a legitimate TCP winner fails its strict capture requirements.
The frame extractor distinguishes the v1 and v2 long-header packet-type fields.

## Capture an ordinary browser

```sh
node tests/tools/echresumption/native.mjs chrome /private/NEW_CHROME_DIR /path/to/chrome h3
node tests/tools/echresumption/native.mjs firefox /private/NEW_FIREFOX_DIR /path/to/firefox h2
```

The runner creates a private isolated profile, sets ordinary Cloudflare Secure
DNS preferences, enables key logging and starts CDP/BiDi automation. Native
certificate verification remains enabled. It records browser version, options,
method and public protocol/ECH trace results in `report.json`.
H3 uses two 45-second idle intervals; optional final argument `fetch` keeps the
same-origin page and performs an ordinary fetch instead of a navigation. Chrome
also accepts `no-cors-fetch`: two warm-up fetches and subsequent requests retain
one about:blank document. Opaque responses establish completion only; their
protocol, accepted ECH, PSK selection and early data must come from the captured
transcript. This mode produced the fresh Chromium 158 references. Browser
shutdown waits for normal exit so NetLog can finish flushing.

Firefox also supports `no-cors-fetch`. Set `SURF_CAPTURE_URL` to an HTTPS endpoint
when that mode should probe a service other than the default trace endpoint.
This changes the requested URL, without forcing HTTP/3 or changing early-data
policy. Opaque completion alone does not identify the negotiated protocol.
`SURF_CAPTURE_DNS=default` retains the browser's own DNS policy instead of the
tool's Cloudflare DoH preference. `SURF_CAPTURE_QLOG=1` enables Firefox's passive
HTTP/3 qlog diagnostic. Firefox opaque mode performs four warm requests and three
45-second idle/repeat cycles; other existing sequences retain their counts.
H2 uses Chrome's socket-pool UI or Firefox's normal hard reload; it does not use
unsupported BiDi cache flags. HTTP/3 availability and resumption are verified
from the resulting capture, never inferred from the requested scenario.

Firefox needs a working display or an ordinary Xvfb desktop in a container.
Run tcpdump separately. Container offload settings may be disabled for accurate
analysis capture; they do not change browser TLS/protocol preferences. Otherwise
record GSO segmentation explicitly and preserve the original capture.

Check capture completeness as well as kernel-drop counters: `frame.cap_len`
must equal `frame.len` for every frame. Linux immediate-mode capture can truncate
offload superpackets at the interface MTU despite a large requested snapshot and
zero reported drops. Use buffered capture, disable UDP segmentation offload when
needed for observation, allow the buffer to drain, and reject truncated evidence.
The early-packet extractor enforces the frame-length check on packet JSON.

## Extract private pairs, then verify and redact

`extract.mjs` outputs a **private** JSON array accepted by the Go verifier.
It does not itself certify ECH acceptance. Supply metadata with `browser`
(e.g. `Chrome/157.0.8103.51`), `platform`, `transport` (`tcp` or `quic`),
`implementation` (`native` or `surf`), and `provenance` containing the input
SHA-256 and exact method. For packet extraction also provide `wire` counts, or
prefer `--wire-json` to compute them from independently decrypted packets.

For Chrome TCP select a single resumed NetLog source:

```sh
node tests/tools/echresumption/extract.mjs --netlog /private/netlog.json --source SOURCE --transport tcp --metadata /private/metadata.json --out /private/NEW_PAIR.json
```

For Chrome QUIC first reconstruct an analysis pcap from actual captured UDP
payloads. Envelopes are synthetic; output is for decoding, not timing claims.

```sh
node tests/tools/echresumption/netlog.mjs /private/netlog.json SOURCE /private/NEW_ANALYSIS.pcap
tshark -r /private/NEW_ANALYSIS.pcap -Y 'tls.handshake.type == 1' -T jsonraw --no-duplicate-keys > /private/outer.json
node tests/tools/echresumption/extract.mjs --netlog /private/netlog.json --source SOURCE --transport quic --outer-json /private/outer.json --metadata /private/metadata.json --out /private/NEW_PAIR.json
```

For Firefox use its stock NSS ECH key log with TShark. Select the ClientHello
and matching server handshake frames of **one complete connection**; preserve
the whole capture for reassembly. Extract using `-T jsonraw --no-duplicate-keys`
or `-T json -x --no-duplicate-keys`. Then:

```sh
node tests/tools/echresumption/extract.mjs --packet-json /private/selected-handshakes.json --metadata /private/metadata.json --out /private/NEW_PAIR.json
```

For Surf add `--keylog /private/surf.keys` to associate its captured expanded
inner send attempt with the actual wire outer random. Incomplete CRYPTO/TCP
fragments are skipped only when a complete reassembled message is available;
ambiguous pairs and conflicting retransmissions fail extraction.

Some ECH secret labels need an analysis lookup alias between inner and outer
randoms. Generate it from the private pairs; key bytes remain unchanged:

```sh
node tests/tools/echresumption/extract.mjs --keylog /private/original.keys --alias-pairs /private/pairs.json --out /private/NEW_ANALYSIS.keys
```

Use that analysis key log with TShark `-T json -x --no-duplicate-keys` and select
all packets of the connection. `--wire-json /private/decrypted-connection.json`
counts actual early QUIC packets/control streams/request streams. It rejects
undecrypted early packets, understands QUIC v1/v2, implicit STREAM lengths and
coalesced packets. A UDP five-tuple can be reused: select by QUIC connection
identity, not only `udp.stream`. For NSS, the ClientHello alone supplies the
expanded inner/outer mapping; exported `expandNSS` and `analysisKeyLog` helpers
also support preparing aliases before the server handshake is decrypted.

Finally verify the original transcript and write **new** sanitized references:

```sh
go run ./tests/tools/echresumption -input /private/pairs.json -out /path/to/NEW_REFERENCE_DIR
go run ./tests/tools/echresumption -keylog /private/surf.keys -record 2 -reference tests/testdata/wire/ech/resumption/native/firefox-160-quic-1.json
```

The verifier validates all captures before creating output. It refuses existing
directories, removes incomplete output on write failure, masks private PSK fields
and never publishes raw EncryptedExtensions. A comparison mismatch exits with an
error; known gaps are reported rather than silently normalized away.

The custom `UTLS_ECH_INNER_CLIENT_HELLO` label is diagnostic, contains private
handshake material and appears only with an explicitly supplied `KeyLogWriter`.
Treat complete NetLogs, browser profiles, traffic keys, pcaps and raw pair JSON
as private. Only the Go tool's sanitized results belong in `testdata`.

CI runs offline Go regression tests plus `node --test` for both capture analyzers.
See the [reference report](../../testdata/wire/ech/resumption/README.md) for
observed matches, the explicit Chrome RTT-history gap and capture limitations.
