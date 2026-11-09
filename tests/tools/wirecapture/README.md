# Independent browser sequence capture

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
node tests/tools/wirecapture/run.mjs --out=/tmp/surf-browser-sequences
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

Each case has three consecutive connections:

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
