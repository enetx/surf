# Browser behavior inventory

This is the working register for source-confirmed differences and missing browser
evidence. Add a row whenever an audit, capture or test discovers a difference.
Keep the browser version, primary source, implementation and remaining evidence
together. An implementation passing local tests does not establish full browser
parity. Close a row only for the explicitly recorded scope; retain capture and
platform limitations instead of silently treating them as a match.

Statuses: **in progress**, **implemented**, **open**, **unverified**.

| ID | Scope | Expected behavior and current status | Evidence / follow-up |
| --- | --- | --- | --- |
| SESSION-01 | Chrome 158 QUIC tickets | **Implemented.** Keep two newest tickets per server, consume each once, discard the entry when its next ticket expires. | [QUICHE cache](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/crypto/quic_client_session_cache.cc); [profile](profiles/chrome/quic/session_cache.go), [queue tests](tests/tlscache/cache_test.go). |
| SESSION-02 | Chrome 158 TCP tickets | **Implemented.** Two TLS 1.3 tickets, newest first, single use; legacy TLS 1.2 tickets remain reusable. | [SSLClientSessionCache](https://github.com/chromium/chromium/blob/158.0.8127.18/net/ssl/ssl_client_session_cache.cc); [profile](profiles/chrome/common/session_cache.go). |
| SESSION-03 | Firefox 160 ticket queues | **Implemented.** Ten tokens per server, earliest expiration first; equal-expiry new tokens go first. Retrieval removes the token. | [SSLTokensCache](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/base/SSLTokensCache.cpp), [defaults](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/modules/libpref/init/StaticPrefList.yaml); [profile](profiles/firefox/desktop/session_cache.go). |
| SESSION-04 | QUIC version from a ticket | **Implemented.** Firefox desktop restores the version from a usable ticket. Chrome 158 defaults to v1, so its profile does not select a version from the ticket. Fallback to older queued tickets is covered by regression tests. | [Firefox token restoration](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs#L774), [Chrome defaults](https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_context.h#L17); [capture report](tests/testdata/wire/session_version/README.md). |
| SESSION-05 | Firefox resumed initial RTT | **Implemented.** Neqo stores RTT in its resumption token and restores whole milliseconds. QUIC records measured RTT; Surf owns restoration precision. No fabricated measurement or new wire parameter. | [Neqo token creation/restoration](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs); [runtime](internal/http3/session_versions.go). |
| SESSION-06 | Chrome 0-RTT rejection | **Implemented.** A rejection disables early data on the remaining queued tickets without resurrecting the consumed ticket or disabling ordinary resumption. | [HandleZeroRttReject](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/tls_client_handshaker.cc); [runtime](internal/http3/session_cache.go). |
| SESSION-07 | Changed QUIC state | **Open application-state audit.** Version, issuing connection and remembered transport limits group queued tickets. A changed connection context discards older tickets. Remembered HTTP/3 SETTINGS and complete 0-RTT application-state validation require a separate audit. | [QUICHE Insert](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/crypto/quic_client_session_cache.cc); [profile grouping](profiles/chrome/quic/session_cache.go). |
| SESSION-08 | Application cache ownership | **Implemented.** Explicit caches retain their semantics. TCP bridges the actual supplied cache, separately from QUIC, rather than silently creating an unrelated cache. SessionTicketsDisabled must take precedence. | [TCP integration](ja_roundtripper.go), [nested cache builder](session_cache.go), [wire regressions](tests/session_cache_test.go). |
| SESSION-09 | TLS 1.2 ticket expiration metadata | **Unverified.** Current public Go/uTLS bridge exposes TLS 1.3 expiry, but not the complete TLS 1.2 server lifetime hint. Cache checks certificate validity and TLS still validates resumption; exact legacy expiry parity is not claimed. | Audit native TLS 1.2 ticket lifetime/reissue behavior before changing the TLS engine. |
| SESSION-10 | Chrome TCP expired head | **Implemented.** An expired selected ticket causes one cache miss, leaving an older usable ticket for the next connection. QUIC separately discards an entry with an invalid head. | [Chrome TCP Pop/ExpireSessions](https://github.com/chromium/chromium/blob/158.0.8127.18/net/ssl/ssl_client_session_cache.cc); [expiry regression](tests/tlscache/cache_test.go). |
| CACHE-01 | Firefox memory eviction | **Open.** Firefox bounds compressed token bytes and evicts by expiration. Surf currently has a bounded number of cache keys. Ten-token ordering is a separate, testable scope. | [Firefox cache accounting](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/base/SSLTokensCache.cpp); requires a defined cross-engine accounting model and eviction captures. |
| CACHE-02 | Disk persistence | **Open.** Surf keeps client-local runtime state. Browser disk persistence is not implemented. | Remains separate from ticket queue and initial-version restoration; do not add persistence implicitly. |
| RACE-01 | Early-ready protocol selection | **Implemented.** Chrome can select early-ready QUIC; Firefox keeps a TCP backup until confirmation. Unsafe bodies wait for selection. | [source/capture report](tests/testdata/wire/early_racing/README.md), [regressions](tests/http3_early_racing_test.go). Complete browser multi-address/resource scheduling is not claimed. |
| ECH-01 | Desktop resumed ECH inner | **Implemented for retained references.** Stable inner features match retained captured Chrome 157 and Firefox 160 TCP/QUIC handshakes. | [native references and limits](tests/testdata/wire/ech/resumption/README.md). New observations must retain actual confirmation and PSK checks. |
| RTT-01 | Chrome per-origin RTT history | **Implemented.** Direct connections advertise measured cached RTT; local recovery clamps independently. Proxy and failed-handshake exclusions are tested. | [source/capture report](tests/testdata/wire/ech/resumption/RTT.md), [wire tests](tests/quic_rtt_history_test.go). |
| MOBILE-01 | Chrome 158 Android | **Unverified on a native Android capture.** Uses shared Chromium session policy and its own Android wire profile. Desktop captures do not establish Android packet timing parity. | [variant](profiles/chrome/variants.go), [Android profile](profiles/chrome/android/http3.go). Need native Android ticket/racing captures. |
| MOBILE-02 | Firefox Android | **Open.** Still an explicitly labeled Firefox 148 placeholder; its variant does not install the desktop QUIC factory. No claim of Firefox 160 Android parity. | [variant](profiles/firefox/variants.go). Obtain current Android TLS/H2/H3/QUIC references before replacing values or wiring a desktop template. |
| IOS-01 | Chrome / Firefox iOS | **Open.** Current profiles do not establish native WebKit TLS-ticket/HTTP3 behavior. Chrome iOS's existing TCP template does not resume in Surf's tests. | [Chrome WebKit controller](https://github.com/chromium/chromium/blob/158.0.8127.18/ios/web/web_state/ui/crw_web_controller.mm), [profile tests](tests/chrome_session_test.go). Need native iOS references; do not copy desktop policies. |
| WIRE-01 | OS packet timing / loss / pacing | **Unverified beyond each recorded scenario.** Source-selected recovery controls and local regressions do not prove every native timing, offload, congestion or resource-scheduling behavior. | [wire evidence and individual limits](tests/testdata/wire/README.md). Retain raw-capture provenance and distinguish analysis envelopes from NIC observations. |

All browser constants and cache policies belong in Surf profiles. Existing
forks expose generic protocol mechanisms only. Public cache settings are available
through `Builder.SessionCache()` and its terminal `Set()`, matching the other
Surf sub-builders. Profiles configure the same concrete fluent cache settings. Explicit application cache
choices take precedence over automatic browser-owned queues.

Go cache housekeeping is unrelated to this inventory: clear build caches only
when disk space is low. Do not delete downloaded module caches as routine cleanup.

## Verification for the ticket-cache implementation

The [session capture report](tests/testdata/wire/session_cache/README.md) records
new verified Surf ECH/resumption connections, an independent v1-to-v2/RTT
restoration peer and the exact scope of fresh native-browser observations.
Queue exhaustion, concurrency, rejection, custom ownership, protocol isolation
and nested-builder behavior are covered by deterministic regressions.

## Current Chromium revision

The [Chromium 158 audit](tests/testdata/wire/chrome_158/README.md) records the
primary source pins and independent native endpoint observations. Chromium is
the protocol reference; Surf keeps Chrome's User-Agent for the selected OS.
The obsolete 157 public profile helpers are removed. Historical captures keep
their original version labels.

| ID | Scope | Expected behavior and current status | Evidence / follow-up |
| --- | --- | --- | --- |
| CHROME-01 | Chromium 158 TCP/H2/H3 wire fields | **Implemented for the observed desktop scenario.** JA4, H2 settings/window, ordered navigation headers, H3 normalized TLS and QUIC parameter values match native Chromium 158. | [Native comparisons](tests/testdata/wire/chrome_158/README.md); Mac arm64 snapshot 1727489. Windows/Android are source-derived variants, not native packet captures. |
| CHROME-02 | TLS server padding 0x12e0 | **Implemented.** Request zero bytes in desktop/Android TCP and QUIC; ECH inner retains the extension. uTLS validates response presence and exact requested length against the actual negotiated hello. | [BoringSSL extension implementation](https://github.com/google/boringssl/blob/ea9f3a34c3977144c45d272be81842fd891a0bdb/ssl/extensions.cc); [wire tests](tests/chrome_experimental_wire_test.go), uTLS parsing/validation tests. Peer omission is valid. |
| CHROME-03 | NOIP connection option | **Implemented on the wire; full pooling policy open.** Native Chromium advertises ORIGNOIP and Surf now does too. Cross-origin connection reuse with waived IP matching is not implemented by advertising the option. | [Chromium session pool](https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_session_pool.cc); native H3 comparison. Audit certificate, origin and privacy isolation before adding connection coalescing. |
| RETRY-01 | Response headers commit a transaction | **Implemented.** No HTTP/3-to-TCP replay after any valid response headers, including 100/103, or a response callback error. Existing TCP policy remains covered. | [Chromium transaction state](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_network_transaction.cc); [network regressions](tests/http3_response_progress_test.go), atomic backup race tests. |
| ECH-02 | Fresh Chromium 158 resumed inner reference | **Unverified native reference.** Current Surf completes verified accepted ECH and resumed H2/H3 connections with the new extension. Fresh Chromium Secure DNS capture attempts timed out during navigation; no complete native ECH/PSK transcript is claimed for 158. | Retained 157/Firefox 160 native references still test the unchanged policy code; new network regressions verify that 0x12e0 survives real accepted ECH/HRR/resumption. Obtain a complete authenticated 158 native capture. |
| BATCH-01 | Native Linux batched reads | **Unverified.** Chromium 158 enables its multiple-read path on Linux/ChromeOS/Android. Surf already uses the QUIC engine's Linux batch reads; identical batch scheduling and packet timing are not established. | [Chromium features](https://github.com/chromium/chromium/blob/158.0.8127.18/net/base/features.cc); requires a native Linux capture. |
| WEBTRANSPORT-01 | New stream hints, draining, reliability API | **Open API scope.** These belong to dedicated WebTransport sessions; ordinary HTTP/3 profile settings were retained from the native capture. | [Feature audit](tests/testdata/wire/chrome_158/README.md). Surf does not claim a complete WebTransport API. |
