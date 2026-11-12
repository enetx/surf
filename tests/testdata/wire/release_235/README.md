# Desktop browser audit — Surf v1.0.235

The reference browsers are ordinary visible Chromium 158.0.8127.0 and Firefox
160.0. Fresh isolated profiles used normal DNS, certificate validation and
protocol selection. Passive CDP/BiDi, NetLog, key logging and packet observation
do not replace the browsers' ClientHello or connection policies. Surf uses the
selected Chrome product identity; native Chromium's two-brand list remains an
explicit difference, including its effect on compressed header length.

[Chromium observations](chromium.json) and [Firefox observations](firefox.json)
retain the comparison scope, decoded results, original artifact hashes and
limitations. The detailed local evidence is in `/tmp/surf-final-audit` and
`/tmp/surf-header-refactor`; these paths are not test dependencies. Original
secret-bearing logs stay outside git. Historical independent goldens are retained
with their actual browser version and capture provenance.

The [final endpoint controls](final_probes.json) repeat eight verified-TLS H2/H3
requests across both profiles and their macOS/Windows identities. All 48 stable
comparisons against the audited outputs pass, including complete H2 reports and
Firefox's corrected extension tail. These are fresh Surf controls; they do not
turn the Windows identity into a native Windows browser capture.

| Area | Result and regression evidence |
| --- | --- |
| TCP TLS | Full stable ClientHello fields, cipher/key-share/signature/ALPN/ALPS details, normalized JA4 and PeetPrint match the corresponding desktop browser. Existing TLS, ECH, HRR and session regressions remain active. Random values are compared by their structure, never forced equal. |
| HTTP/2 | SETTINGS, connection window, pseudo/regular field order and native HPACK references pass. Fresh Chromium HPACK is byte-identical to its independently retained 443-byte block. Firefox's full navigation report and ordinary GET/POST fetch HEADERS frames match. |
| HTTP/2 request priority | Fixed a confirmed fetch/navigation difference: Chrome wire weight 220/256, Firefox 22/42. Explicit mode wins; a scenario survives suppressed metadata and redirects. Literal Priority is independent. [Wire regressions](../../../header_profile_http2_priority_test.go) cover seven methods, Surf/Std, nil metadata and user overrides. |
| HTTP/2 exhausted receive window | A final Linux run exposed a generic override that sent 2,129,920 bytes of credit below Chrome's half-window threshold. Source inspection confirmed that zero peer-visible credit does not force an update while unread bytes remain buffered. The installed policy now owns that choice; Firefox's explicit emergency condition and native Go's nil-policy path remain intact. [Deterministic wire barriers](../../../http2_receive_window_exhausted_test.go) send a full 6 MiB window, then verify no update at 32 KiB or exactly half, and an update at half plus one, followed by successful completion. |
| HTTP/3 and QUIC | Stable TLS fields, settings, transport parameters, CID lengths and complete ordered headers match the observed desktop scenario, apart from selected product branding. Chrome fetch PRIORITY_UPDATE remains `u=1, i`. Existing QPACK, ACK, version negotiation, recovery, body framing and connection-racing suites pass. |
| Chrome Initial packet numbers | Fixed the coalesced soft-budget estimate: four native flights encode Initial PN1/PN2 in one/two bytes. Three corrected Surf UDP captures do the same; Handshake/1-RTT reset their width. The engine exposes a generic estimate; Surf owns the browser policy. |
| Firefox TLS extension tail | Fixed permutation of custom senders: built-ins shuffle, QUIC parameters 57 then ECH 65037 follow, and PSK 41 remains last. [Regressions](../../../firefox_quic_extension_order_test.go) validate fresh wire order and authenticated resumed/early-data handshakes, including accepted ECH. |
| Firefox Initial CRYPTO | Fixed source-derived SNI slicing: ordered right/left byte ranges, live packet/frame budgets and remaining unsent ranges. [Four independent native vectors](../firefox_160_initial_crypto.json) and [actual encrypted-UDP regressions](../../../firefox_quic_crypto_layout_test.go) cover differing SNI positions and missing SNI. The final Surf NIC capture retained 55 packets with zero kernel drops. |
| Methods, forms, redirects and streaming | [86 retained native requests](../header_presets/README.md) plus the independent Client Hints corpus preserve full names, casing, values, order and bodies. Local H1/H2/H3 peers exercise all ordinary methods, explicit empty uploads, known/unknown streams, ownership and adapters. H2/H3 matrix cases are not represented as fresh native captures of every scenario. |
| Client Hints | Origin opt-ins, Critical-CH restart, explicit ownership and cookie/body replay are tested. Known navigation remains independent of suppressed metadata; [H1/H2/H3 Surf/Std regressions](../../../client_hints_scenario_test.go) verify negotiation and restart without the emitted fields. Eight independent native metric fetches distinguish the corrected Blink insertion order. Ordinary insecure LAN references verify omitted automatic hints/metadata and gzip/deflate; trusted loopback remains separate. |

Primary source pins were rechecked: 53 Chromium/QUICHE/BoringSSL files and all
30 retained Firefox/NSS/Neqo hashes matched. Relevant policy functions link the
browser sources directly. Generic engine extensions and their update boundaries
are documented in each fork's UPSTREAM.md.

The new header model keeps each browser's identity, defaults, hint positions and
request/protocol scenarios in one `common/headers.go`. Existing public helpers
delegate to it. `g.MapOrd` remains the explicit ordering API; nil/empty regular
order, pseudo order and H1 casing each retain user ownership. `.Fetch()` and
`.Navigation()` are optional scenario selectors, not requirements for ordinary
GET/POST calls.

## Limits retained after this audit

- Fresh Chromium 158 default-DNS captures did not accept ECH and the issued
  tickets did not allow early data. They confirm ordinary resumption and
  single-use ticket order, not a new accepted-ECH/0-RTT browser transcript.
  Existing independent Chrome 157 / Firefox 160 references and authenticated
  engine/network regressions retain their own narrower evidence.
- Firefox SNI layout covers the first complete ClientHello's unsent bytes.
  Whole-flight-loss re-slicing, HRR re-layout and complete native pacing are not
  established. Retransmission keeps the QUIC engine's recovery behavior.
- Chromium NetLog UDP bytes were independently decrypted in synthetic PCAP
  envelopes; those envelopes are not native NIC/IP timing evidence. Separate
  Firefox Linux tcpdump captures and Surf UDP captures retain their own provenance.
- Native Android/iOS and Windows kernel behavior remain unverified. Firefox
  mobile profiles remain explicitly labeled 148 placeholders. A Windows UA
  applied to a macOS/Linux capture does not establish Windows packet behavior.
- DOM policies, arbitrary resource insertion/scheduling, persistence, complete
  remembered HTTP/3 application state and every loss/congestion scenario remain
  the separate scopes recorded in [BROWSER_PARITY.md](../../../../BROWSER_PARITY.md).

[Final validation](validation.json): complete standalone Go race suites and vet
pass on macOS and Linux with `GOWORK=off` and published HTTP v1.0.38 / QUIC
v1.0.21 / uTLS v1.0.6. Production statement coverage is 88.6% on both systems.
Complete engine suites, reproducible HTTP/2 aliases, update-helper tests and all
23 JavaScript analyzer tests pass. The corrected HTTP/2 window wire scenarios
also pass 20 repetitions on each system; generic engine window tests pass 100
race repetitions. [The flow-control record](http2_flow_control.json) keeps the
original failure, source mapping and deterministic before/after evidence.
