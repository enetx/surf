# Chromium 158 reference

Surf's Chrome profile uses **native Chromium as its protocol reference** and
Chrome's User-Agent for the OS selected by the application. The default desktop
OS remains Windows. Google-branded builds can have different field trials;
they are not substituted for the selected Chromium reference.

## Independent observations

The reference is Google's unmodified macOS arm64 Chromium snapshot **1727489**,
version **158.0.8127.0**. It ran as an ordinary visible browser with a fresh
profile. CDP and passive NetLog recording provided observation. There were no
protocol, certificate, resolver, proxy, User-Agent or field-trial bypass flags.
HTTP/3 was discovered through normal Alt-Svc. Public TLS verification remained
enabled. This is not a capture from a native Windows or Android installation.

- [HTTP/2 comparison](http2_comparison.json): TLS JA4, ordered SETTINGS,
  connection window and every navigation header match Surf's MacOS profile.
  The independently recorded SSL socket bytes supply a new exact HPACK oracle
  (448-byte HEADERS frame), retaining the original encoded bytes.
- [HTTP/3 comparison](http3_comparison.json): normalized TLS JA3n, client CID
  length, SETTINGS, header values/order and transport parameter values match.
  Transport parameter permutations differ, as expected for independently
  randomized connections. Tests separately check that permutations vary.
- [HTTP/3 oracle](../chromium_158_http3.json) contains only semantic fields and
  input hashes. Random keys, tickets, IP addresses, profiles and full NetLogs
  are private and are not committed.

The observed TLS extension **4832 (`0x12e0`, `server_padding`)** requests zero
padding bytes (`0000`). It is not extension 62 (`tls_flags`). Desktop and
Android-derived TLS templates, QUIC and the accepted ECH inner preserve it.
uTLS checks a received server-padding response against the actual negotiated
ClientHello and requires the exact requested length, following BoringSSL.
Omission by the server is valid; the response contents are opaque.

The observed Google connection options transport parameter **12584 (`0x3128`)**
contains **`ORIGNOIP`**. It is emitted by default. Advertising NOIP does not
implement Chromium's complete cross-origin connection-pool/coalescing policy.

Client Hints use the observed unbranded list
`"Not.A/Brand";v="24", "Chromium";v="158"`. The chosen OS headers and User-Agent
remain configurable through Surf's existing builders.

## Primary source audit

The release-tag audit uses Chromium **158.0.8127.18** and its pinned QUICHE and
BoringSSL revisions:

- [Chromium DEPS](https://github.com/chromium/chromium/blob/158.0.8127.18/DEPS).
- [QUICHE 132bfd90ea370faeacee616c70d10210bb12ba66](https://github.com/google/quiche/tree/132bfd90ea370faeacee616c70d10210bb12ba66).
- [BoringSSL ea9f3a34c3977144c45d272be81842fd891a0bdb](https://github.com/google/boringssl/tree/ea9f3a34c3977144c45d272be81842fd891a0bdb).
- [Source manifest and SHA-256 values](sources.json).

Core SETTINGS, HPACK/QPACK, ticket selection, congestion control, ACK thresholds
and packet-layout defaults were checked against the retained 157 audit. The
Chromium field-trial configuration explains the observed server-padding and
NOIP additions; Surf follows the selected native capture rather than disabling
those trials to obtain a different result.

Chromium 158's transaction handling stops protocol retries once any response
headers, including 100 or 103, have arrived. Surf now enforces that rule for
HTTP/3 fallback and early TCP backup as well as its existing HTTP/2 path.
`HTTP3Settings().OnResponseHeaders(...).Set()` observes every valid header block;
errors abort the request. `Got1xxResponse` errors are also propagated by HTTP/3.
Network regressions cover closure before headers, closure after 100/103,
callback errors, final success and concurrent backup commitment.

## WebTransport entries supplied for this audit

- [Anticipated concurrent incoming streams](https://chromestatus.com/feature/5089961022980096).
- [Session draining](https://chromestatus.com/feature/6427766428925952).
- [Reliability attributes](https://chromestatus.com/feature/5094058497277952).

These concern the dedicated WebTransport session and its JavaScript API, not
ordinary HTTP/3 GET/POST connections. Stream-count hints are applied in the
dedicated WebTransport client; draining/reliability are session API behavior.
They do not justify changing the captured HTTP/3 SETTINGS or QUIC flow-control
limits. Surf does not claim to expose a complete WebTransport API.

## Fixture provenance and remaining evidence

The new MacOS golden includes the fresh native 158 HPACK bytes. The other
`chrome-158-*.golden` files combine independently captured desktop TLS
fields with source-derived OS identities and existing platform H2 settings.
The desktop server-padding field is independently observed above. Windows and
Android identities are not new native captures from those platforms. iOS uses
the official 158 app build **158.0.8127.32** over the retained WebKit transport
template; server padding and desktop QUIC are not applied to iOS.

The retained 157 Mac HPACK byte oracle and iPhone HEADERS-length oracle still
run with their original headers. They preserve independent compression tests
without relabeling an old capture as 158. Historic 157 ECH fixtures remain
truthfully labeled; a fresh complete Chromium 158 ECH/resumption capture is
tracked separately in the behavior inventory.

[Current Surf ECH packet observations](ech_capture.json) record six verified
connections, accepted ECH, four resumed sessions and server padding in all outer
and expanded inner hellos. All 134 packets were captured with zero kernel drops.

Linux's newly enabled native batched-read path, native Windows packet timing,
Android/iOS runtime behavior, all loss/congestion scenarios and full cross-origin
coalescing remain outside this capture's evidence. See
[the behavior inventory](../../../../BROWSER_PARITY.md).

## Release validation

Full race suites and vet passed on macOS for Surf, QUIC and uTLS, including
standalone fork-module runs. Surf's Linux race/coverage suite and vet passed;
production coverage is **87.7%** with the same package selection as CI. All
23 Node capture-analysis tests passed. The current Mac HPACK byte oracle and
response-progress regressions also pass independently. Published-dependency
Surf validation runs with `GOWORK=off` so no local replacement can hide a
missing release dependency.
