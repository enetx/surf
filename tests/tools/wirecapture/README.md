# Ordinary browser references and local wire diagnostics

Use `native-endpoint.mjs` for actual browser behavior on publicly trusted HTTPS.
It launches an ordinary visible Chromium or Firefox with a fresh isolated profile
and automation/UI controls only. It does not force QUIC, alter protocol preferences,
override User-Agent, change proxy/resolver policy or bypass certificate validation.
The browser learns HTTP/3 through the endpoint's normal Alt-Svc response. Repeated
navigations allow discovery to complete; these are fingerprint snapshots, not a
measurement of connection-racing timers or application scheduling.

```sh
node tests/tools/wirecapture/native-endpoint.mjs --browser=firefox --out=/tmp/firefox-native
node tests/tools/wirecapture/native-endpoint.mjs --browser=chrome --out=/tmp/chromium-native
node tests/tools/wirecapture/native-endpoint-analysis.mjs --browser=/tmp/firefox-native --surf=/tmp/surf-firefox --out=/tmp/firefox-native-comparison.json
```

Exact large endpoint integers require Node 22+ JSON source context; Node 26 is the
tested manual-tool environment. Raw endpoint responses and profiles stay private.
The analyzer normalizes GREASE entropy and SCIDs, while preserving version
capabilities, headers and the observed transport-parameter order.

The older `run.mjs` and `firefox-endpoint.mjs` are **diagnostic tools**. They require
explicit `--diagnostic=true`, because they force protocols and use local trust
overrides. Their captures can check encoders and transport mechanics; they are not
ordinary browser behavior references. In particular Firefox's forced Alt-Svc
testing preference also disables HTTP/2, affecting its TCP fallback. A local
private CA is insufficient to claim ordinary QUIC selection: Chromium additionally
checks whether a QUIC chain has a known root. Controlled loss/racing comparisons
without overrides need a publicly trusted TLS peer that we control.

## Local diagnostics

This manual macOS tool runs installed Chromium and Firefox against a private
local TLS/QUIC peer, then repeats the requests using Surf on the same origin.
Browsers use new disposable profiles. Firefox trusts the generated CA only in
its temporary NSS database; Chromium receives a per-process SPKI allowlist.
The tool never opens or changes a personal browser profile or global trust store.

Requirements: Go 1.27, Node with built-in WebSocket support (tested with 26.13.0),
Chromium at `/Applications/Chromium.app`, Firefox at `/Applications/Firefox.app`,
Wireshark CLI (`tshark`, tested with 4.6.9) on PATH, and Homebrew NSS `certutil`.
Browser executable and `certutil` paths are explicit in `run.mjs`; change them
for another installation. The offline Go regression tests are portable and need
none of these browser tools.

Run from the Surf module root:

```sh
go build -o /tmp/surf-wirecapture ./tests/tools/wirecapture
node tests/tools/wirecapture/run.mjs --diagnostic=true --out=/tmp/surf-browser-sequences
node tests/tools/wirecapture/analyze.mjs --in=/tmp/surf-browser-sequences --out=/tmp/surf-browser-analysis
go test -race -run TestIndependentBrowser ./tests ./tests/tools/wirecapture
```

Use a new output directory for every capture; existing case directories are
rejected. To limit a run, add `--browser=firefox --protocol=h3 --capacity=0,4096`.
The default matrix has two HTTP/2 cases and eight HTTP/3 cases. It rejects
protocol fallback or an incomplete sequence. Browsers are controlled through
their own CDP/BiDi protocols without an additional automation package.

The scenario navigates to a page and performs nine awaited same-origin fetches,
followed by a completion fetch. Cookies have 19-, 20- and 202-byte pairs; a later
response replaces the shortest pair with a 20-byte pair. Authorization is absent,
repeated, changed and removed. All credentials are fixed synthetic strings.
HTTP/2 sends repeated and changing peer table settings through
4096 → 4096 → 65536 → 65536 → 128 → 4096 → 0 → 4096.
HTTP/3 uses a separate connection for each peer capacity (0, 128, 4096, 65536);
it never sends an illegal second SETTINGS frame.

Each case has three consecutive client runs; reconnection can add connections:

1. Actual browser navigation and JavaScript fetches.
2. Surf's stock desktop preset and cookie jar (`surf-preset`). This deliberately
   shows the difference between navigation defaults and a browser's fetch context.
3. The same Surf transport with exactly the browser's ordered input fields,
   bypassing request middleware (`surf-exact-input`). This isolates the encoder
   and frame behavior. Header map keys use Go's canonical form; wire order is
   passed separately. The original authority is preserved for offline replay.

The peer records exact TLS byte streams and QUIC UDP datagrams. `wire.pcap` uses
synthetic IPv4/TCP envelopes so Wireshark can independently decrypt and decode
the protocol without privileged packet capture. **IP/TCP fingerprints, TCP
segmentation, socket timing, congestion, packet pacing and loss behavior cannot
be assessed from this file.** Wrapping the UDP socket also disables the native
OOB/GSO fast path. This is an HTTP encoding/control-frame experiment.

`analyze.mjs` checks decoded Wireshark fields against the peer's ordered fields
and checks HTTP/2 raw block bytes against the peer's raw blocks. Its bounded RFC
9204 parser inspects actual QPACK field representations, N bits and Huffman bits
without importing Surf's codec. It rejects missing sections, duplicate streams
and ambiguous connection attribution. Sections for which Wireshark emits no
decoded fields are counted explicitly, never treated as an independent match.
The receiving peer's fields remain available for those sections.

Raw pcaps, TLS secrets, temporary certificates and profiles stay in the private
output directory (key files are mode 0600). Keep that directory outside Git.
The committed fixtures contain synthetic headers, raw browser header blocks,
capture hashes, browser metadata and comparison results, without TLS secrets.
To regenerate them **only after reviewing a fresh browser capture**, add:

```sh
node tests/tools/wirecapture/analyze.mjs --in=/tmp/surf-browser-sequences --out=/tmp/surf-browser-analysis --fixtures=tests/testdata/wire/browser_sequences
```

The report at `tests/testdata/wire/browser_sequences/README.md` documents the
measured matches, differences and decoder limits. These fixtures supplement the
existing navigation snapshots; they do not replace them with Surf-generated data.

## ACK observations

To exercise ACK behavior beyond the packet-number transition, request a 2 MiB
synthetic response on `/step/0` and retain server-side decrypted QUIC frame traces:

```sh
go build -o /tmp/surf-wirecapture ./tests/tools/wirecapture
node tests/tools/wirecapture/run.mjs --diagnostic=true --out=/tmp/surf-ack-observations --protocol=h3 --capacity=0 --response-bytes=2097152 --decode=false
node tests/tools/wirecapture/ack-analysis.mjs --in=/tmp/surf-ack-observations --out=/tmp/surf-ack-summary.json
```

`transport.jsonl` records server 1-RTT packets and actual incoming ACK ranges.
The analyzer counts newly acknowledged server ack-eliciting packets and splits
early/late observations at span 100 from the first server 1-RTT packet number.
These ratios include piggybacking, buffering and tracing overhead; an observed
ACK can acknowledge more packets than its triggering threshold. Reported ACK
delays are not a guarantee about NIC transmit timing. `--decode=false` skips the
large Wireshark JSON output; raw pcap and TLS secrets remain private as before.

## Request bodies and explicit priorities

The optional `--scenario=uploads --protocol=h3` run sends nine POST bodies of
1 through 400000 bytes. Surf repeats the same method/body and records DATA
boundaries in `frames.jsonl`. `--scenario=priorities --protocol=h3` changes a
visible image's `fetchPriority` during a slowly streamed SVG response. Its exact
Surf replay exercises explicit manual updates; it does not claim the web API
caused those updates in a browser. Both scenarios work with capacities 0 and
65536. Use a separate fresh output root for each scenario/repeat.

```sh
node tests/tools/wirecapture/run.mjs --diagnostic=true --binary=/tmp/surf-wirecapture --out=/tmp/surf-uploads --protocol=h3 --capacity=0,65536 --scenario=uploads
node tests/tools/wirecapture/run.mjs --diagnostic=true --binary=/tmp/surf-wirecapture --out=/tmp/surf-priorities --protocol=h3 --capacity=0,65536 --scenario=priorities
node tests/tools/wirecapture/behavior-analysis.mjs --in=/tmp/surf-uploads,/tmp/surf-priorities --out=/tmp/surf-behavior.json
```

`behavior-analysis.mjs` attributes connections by original QUIC destination ID,
checks every recorded DATA/PRIORITY_UPDATE against independent Wireshark lengths
and values, and preserves observed reconnections. Mismatching browser/Surf DATA
boundaries are recorded, never converted into successful exact comparisons.
`analyze.mjs` is the original 11-request header/QPACK sequence analysis; use the
behavior analysis for these experiments, especially the three-request image run.

## Transport comparison

For Initial CRYPTO ordering, DCID lengths, Handshake datagram composition, PINGs,
MAX_DATA/MAX_STREAM_DATA and HTTP/2 WINDOW_UPDATE, use 10 MiB bulk responses and
run the independent transport analyzer:

```sh
go build -o /tmp/surf-transport ./tests/tools/wirecapture
node tests/tools/wirecapture/run.mjs --diagnostic=true --binary=/tmp/surf-transport --out=/tmp/surf-transport-capture --protocol=h2,h3 --capacity=0 --response-bytes=10485760 --decode=false
node tests/tools/wirecapture/transport-analysis.mjs --in=/tmp/surf-transport-capture --out=/tmp/surf-transport-report.json
```

The HTTP/2 peer splits DATA into at most 16 KiB frames and obeys both credit
windows. The analyzer invokes Wireshark, attributes each decoded connection to
browser/preset/exact-input requests and rejects incomplete sequences. It keeps
semantic frames and UDP payload sizes; synthetic TCP envelopes cannot establish
TCP segmentation or NIC timing. The committed report summarizes credit-update
histograms instead of retaining thousands of repetitive entries. Do not treat a
matching frame count as proof of complete packet scheduling or loss parity.

The transport analyzer also reports decoded packet-number length histograms,
the first application packet, the first Handshake packet and the separate flight
carrying client Finished. It records padding outside coalesced QUIC packets
separately. Undecoded packet numbers remain explicitly unknown. Wireshark nests
short headers and emits metadata-only padding objects, so the parser has its own
regressions:

```sh
node --test tests/tools/wirecapture/transport-packet.test.mjs
```

Transport reports retain encoded packet sizes, ACK delay fields and the ordered
NEW_CONNECTION_ID sequence numbers. Initial datagram tails are counted as zero
and nonzero bytes separately; the dissector's generic `(Random) padding` label
does not establish randomness. The control-stream prefix decoder reports actual
SETTINGS varint lengths and reserved-frame payload sizes, allowing GREASE size
variation to be distinguished from packet framing differences. Its vectors come
from captured Chromium and Surf prefixes and contain no TLS secrets.

## Controlled UDP delay and loss

The local HTTP/3 peer can apply a constant delay in each direction and a
repeatable drop rule independently for each remote UDP address and direction:

```sh
node tests/tools/wirecapture/run.mjs --diagnostic=true --binary=/tmp/surf-wirecapture --out=/tmp/surf-delay-loss --protocol=h3 --capacity=0 --response-bytes=2097152 --decode=false --udp-delay=10ms --udp-drop-every=37
node tests/tools/wirecapture/ack-analysis.mjs --in=/tmp/surf-delay-loss --out=/tmp/surf-delay-loss-acks.json
```

`--udp-delay` accepts Go durations from zero through one second. Ten milliseconds
in both directions adds about 20 ms of RTT. `--udp-drop-every=N` drops every Nth
datagram (zero disables, N must be at least two). `--udp-drop-first=N` drops the
first N datagrams (0..10), then the periodic rule starts. Each queue is bounded to
4096 packets; `network-summary.json` reports observed, dropped, delivered and
overflow counts, plus transport/logging errors. `network.jsonl` retains private
per-flow events. A few queued packets may remain undelivered during shutdown.

Delay is pipelined through separate read/write schedulers. It does not sleep in
`WriteTo` and impose an accidental bandwidth limit. Incoming pcap datagrams are
recorded before emulated loss/delay; outgoing datagrams after it, at the actual
socket write. Thus a dropped incoming packet still appears in pcap. These are
application-level socket experiments, with OOB/GSO disabled, not kernel netem or
NIC captures. They establish frame/ACK observations, not browser pacing,
congestion control or loss-recovery equivalence.

ACK analysis keeps sent/acknowledged packet sets separately for each connection,
then aggregates observations by client label. Reconnection can reuse packet
numbers without conflating ACKs. Node regressions cover this and bounded range
processing; CI runs all `*.test.mjs` analyzers.

Failed navigations retain `browser.json`, logs and `failure.json` with the peer
status. They remain failed runs. Before HTTP/1.1 support was added, the first-datagram-loss experiment failed
when Firefox attempted HTTP/1.1 TCP fallback against the HTTP/2-only peer. Its
`NS_ERROR_NET_RESET` remains an incomplete historical experiment. The completed
replacement scenarios are documented below; browser connection racing remains
different from Surf.

## Fallback and packet reordering

The TCP peer offers both h2 and http/1.1 and accepts HTTP/1.1 without ALPN. Its
bounded header capture preserves raw spelling/order/repeated fields while using
the same buffered reader for body framing and pipelined requests. It serves the
same synthetic scenario over all three protocols. The default runner still
requires the selected protocol for both browser and Surf. Explicitly allow mixed
protocols for a fallback investigation:

```sh
node tests/tools/wirecapture/run.mjs --diagnostic=true --binary=/tmp/surf-wirecapture --out=/tmp/surf-fallback --protocol=h3 --capacity=0 --response-bytes=2097152 --decode=false --udp-delay=10ms --udp-drop-first=1 --allow-fallback=true
node tests/tools/wirecapture/fallback-analysis.mjs --in=/tmp/surf-fallback --out=/tmp/surf-fallback-report.json
```

`comparison.json` preserves per-client request protocols and connection attribution.
The fallback analyzer independently decrypts HTTP/1 requests with Wireshark and
compares method, URI and source port with peer records. It measures the first TCP
ClientHello relative to the first UDP Initial at the capture socket, not SYN or
browser scheduling timestamps. Its summary excludes secrets, profile paths and
session identifiers. A case directory can be supplied instead of a whole root.
Fallback replay compares transport behavior; it is not an exact cross-protocol
header-encoding comparison. Full expected request counts are still required.

Add `--udp-jitter=5ms --udp-reorder-every=17` to a 10 ms one-way-delay run to vary
packet delay and permit overtaking. Jitter uses a fixed independent PRNG per
remote/direction for reproducibility, uniformly within +/- the requested duration;
it must not exceed the base delay. Every Nth datagram is delayed by an additional
max(1 ms, twice the base delay). Reordering is observed, not guaranteed when
traffic is sparse. Summary counters include actually delivered reordered packets.
A bounded deadline heap permits later packets to overtake delayed ones; both its
storage and each admission queue are limited to 4096 entries. Zero options retain
the original constant-delay FIFO scheduler. Deadline and Close behavior is tested.

## Direct Firefox endpoint references

`firefox-endpoint.mjs` navigates an isolated installed Firefox to a public
fingerprint endpoint. The selected protocol is verified from the response.
Windows mode overrides only the browser User-Agent; the host kernel remains
macOS. No normal browser profile is modified. HTTP/1.1 uses the current
`network.http.http2.enabled` preference to disable HTTP/2.

```sh
node tests/tools/wirecapture/firefox-endpoint.mjs --diagnostic=true --out=/tmp/firefox160-peet --os=windows --protocol=h2
/tmp/surf-wirecapture -browser=firefox -os=windows -protocol=h2 -probe-endpoint=https://tls.peet.ws/api/all -out=/tmp/firefox160-surf
node tests/tools/wirecapture/peet-golden.mjs --browser=/tmp/firefox160-peet/browser-endpoint.json --surf=/tmp/firefox160-surf/surf-endpoint.json --out=/tmp/firefox160.golden --report=/tmp/firefox160-comparison.json
```

Use `h1` for an independent HTTP/1.1 reference. `peet-golden.mjs` compares full
HTTP/1.1 or HTTP/2 endpoint sections and normalized TLS before writing a browser
golden. For HTTP/3, pass `--protocol=h3 --url=https://fp.impersonate.pro/api/http3`
to the browser script; `http3-golden.mjs --in=BROWSER_JSON --out=REFERENCE_JSON`
extracts a browser-only reference. Browser responses, TLS keys and temporary
profiles remain private; committed reports contain normalized fields and hashes.

## Connection-racing validation

Surf's offline Go tests prepare HTTP/1, HTTP/2 and HTTP/3 connections without
touching streaming bodies. They exercise cancellation, shared waiters, body
factories, certificate failures, HTTP CONNECT/SOCKS5, late QUIC readiness and
client cleanup. Local browser diagnostics can additionally pass
`--connection-racing=true --allow-fallback=true`; their protocol/trust overrides
must remain identified as diagnostic. Per-client phase bounds prevent a later
Surf TCP handshake from being attributed to an HTTP/3-only browser phase.
`fallback-analysis.mjs` independently verifies HTTP/1 and HTTP/2 request methods,
paths and connection attribution with Wireshark. No unmodified-browser loss/racing
parity is asserted without the publicly trusted controlled peer.

## Outgoing legacy ACK_FREQUENCY

Opt the local server into the Firefox legacy format with
`--legacy-ack-frequency-min=1ms`. Zero keeps the native server behavior. This
advertisement is independent of browser client receiver settings.

```sh
node tests/tools/wirecapture/run.mjs --diagnostic=true --binary=/tmp/surf-wirecapture --out=/tmp/surf-peer-ack --browser=firefox --os=windows --protocol=h3 --capacity=0 --response-bytes=2097152 --udp-delay=10ms --legacy-ack-frequency-min=1ms --decode=false
node tests/tools/wirecapture/peer-ack-frequency-analysis.mjs --in=/tmp/surf-peer-ack --out=/tmp/surf-peer-ack-report.json
```

The analyzer decrypts only client Initial and ACK_FREQUENCY packets, avoiding
large full-decoder output. It binds original DCIDs to Wireshark connection numbers
(one UDP socket can host multiple connections), then compares all received
legacy requests with server qlog. Socket-observed frames dropped by the emulator
are listed separately. Reports preserve browser version, network controls, hashes
and per-connection frame values without TLS keys or temporary profile identifiers.
Older capture metadata can explicitly supply `--peer-min-us=1000`; current runs
record the server minimum directly. Chromium is a negative sender control.


For the current Chrome profile, select the pinned ordinary Chromium 158 executable.
Chromium is the protocol reference; Surf supplies Chrome's selected OS User-Agent:

```sh
node tests/tools/wirecapture/native-endpoint.mjs --browser=chrome \
  --executable="/path/to/Chromium.app/Contents/MacOS/Chromium" \
  --netlog=true --out=/private/new-chromium158-capture
```

The optional NetLog is passive observation stored inside the private capture
directory. No protocol, certificate, resolver, proxy or User-Agent override is
introduced. The active offline fixture/audit is
`tests/testdata/wire/chrome_158/README.md`; historical codec/recovery corpora
retain the versions actually captured.
