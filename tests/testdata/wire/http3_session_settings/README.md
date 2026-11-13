# HTTP/3 SETTINGS bound to TLS tickets

The client now retains the server SETTINGS with each exact TLS ticket. A ticket
received before SETTINGS waits in its issuing connection's bounded queue. A
racing connection cannot provide that state. Missing, malformed or duplicate
metadata preserves ordinary TLS resumption and disables early data. Application
cache keys, ticket ownership and queued insertion order remain intact.

The existing fluent API enables early requests:

```go
client := surf.NewClient().Builder().Impersonate().Chrome().
    Session().SecureTLS().
    HTTP3Settings().EarlyData(true).Set().
    Build().Unwrap()
defer client.Close()
```

This needs no new policy flag or TLS fork. The
[ticket-cache example](../../../../examples/session/ticket_cache/ticket_cache.go)
uses the same API. `SessionCache()` remains the nested builder for cache
overrides; explicit application caches retain their policy.

## Source checks

The implementation was checked against Chromium 158's pinned QUICHE revision
`132bfd90ea370faeacee616c70d10210bb12ba66` and Firefox 160:

- [QUICHE SETTINGS handling and serialization](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/http/quic_spdy_client_session_base.cc).
- [QUICHE setting compatibility and restoration](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/http/quic_spdy_session.cc).
- [QUICHE per-ticket transport/application grouping](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/crypto/quic_client_session_cache.cc).
- [Firefox remembered settings and rejection](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-http3/src/connection.rs).
- [RFC 9114 §7.2.4.2](https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2),
  [RFC 9204 §3.2.3](https://www.rfc-editor.org/rfc/rfc9204#section-3.2.3),
  [RFC 9297 §2.1.1](https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1).

Saved QPACK capacity and blocked-stream limits permit early dynamic encoding.
Every connection has a new table; entries and acknowledgments are never restored
from a ticket. Compatible actual SETTINGS retain entries already inserted on
this connection and avoid a second capacity instruction. Accepted early data
with incompatible settings closes the connection. Known outgoing field-section
limits apply to headers and trailers before encoding. Explicit zero differs from
an omitted limit. Chrome ticket grouping includes canonical server application
state, independent of setting order or measured RTT.
Chromium maps a nonzero table-capacity mismatch to H3_SETTINGS_ERROR; Firefox
reports a decrease as H3_SETTINGS_ERROR and an increase as
QPACK_DECODER_STREAM_ERROR. These choices live in the fluent Surf profiles.
The engine's default follows RFC 9204, with a bounded optional error-code policy.

## Actual network checks

[Observations](observations.json) record the exact scope and sanitized capture
metrics. The raw PCAP, logs and temporary test binaries remain outside git in
`/tmp/surf-h3-resumption`.

- Thirty cases cover native TLS, Chrome and Firefox, each with ten scenarios:
  identical settings, enabling a previously zero table, increasing blocked-stream
  allowance, reducing it, increasing/decreasing a nonzero table, reducing the
  field limit, TLS rejection of early data, explicitly disabled early data, and
  a legacy ticket without HTTP/3 metadata. The complete matrix passes ten
  consecutive repetitions on macOS and Linux.
- A deliberately inconsistent raw peer accepts TLS early data before sending its
  changed SETTINGS. The peer decodes the client's HTTP/3 connection-close error;
  server-side QPACK validation cannot mask that client check.
- A separate raw peer creates a new QPACK decoder for each connection. Its
  resumed TLS handshake waits until a real 0-RTT request packet has been sent.
  Both resumed requests have a nonzero Required Insert Count byte (5), decode
  successfully with the fresh table, and precede the new server SETTINGS.
- TLS rejection now exercises Firefox's same-connection restart; Chrome and the
  native provider retain the existing bounded fresh-connection retry. Changed
  server limits apply normally. The original capture counts below retain their
  historical meaning; [the rejection stage](../early_rejection/README.md) records
  the new Firefox wire evidence and its native-capture limits.
- The Linux loopback capture metrics in `observations.json` include readable
  0-RTT long headers and coalesced packets, with zero kernel capture drops.
  Short-header/GSO tails are not represented as independently decoded packets.
- Existing server oversize-header regressions deliberately send raw HEADERS,
  retaining the server's 431 check now that a conforming client rejects known
  oversize fields locally. Cache ownership tests wait for the SETTINGS-dependent
  cache callback instead of assuming that a response orders independent streams.

Deterministic tests also cover pending tickets before SETTINGS, concurrent
insertion order, opaque keys, invalid metadata, deletion without resurrection,
bounded queues, defensive snapshots, explicit zero, canonical grouping, QPACK
capacity updates, all ordinary request methods and trailer limits. Full engine
and Surf race suites and vet pass on macOS arm64 and Linux arm64. Linux/386
engine test compilation passes. The Linux engine tests run with NET_ADMIN so
upstream force-buffer socket tests can execute.

## Scope retained

This is source-checked behavior plus controlled Surf/QUIC interoperability and
raw UDP observation. It is not a new native Chromium 158 accepted-0-RTT capture;
that independent reference remains open in
[BROWSER_PARITY.md](../../../../BROWSER_PARITY.md). Unknown extensions are retained
without implementing their capabilities. Extended CONNECT still waits for the
actual peer SETTINGS, and full WebTransport behavior is a separate scope.
