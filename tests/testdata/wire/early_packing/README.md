# Early HTTP/3 packet boundaries: Chromium 158 and Firefox 160

This audit separates transport rules from request and OS scheduling. It does not
turn one packet count into a fixed browser constant. `observations.json` retains
sanitized frame ranges, input hashes, native ordered fields and verification
results. Raw NetLogs, qlogs, pcaps, profiles and traffic keys remain private.

## Source decisions

Chromium 158's [DEPS](https://github.com/chromium/chromium/blob/158.0.8127.18/DEPS)
pins QUICHE at `132bfd90ea370faeacee616c70d10210bb12ba66`. In that revision,
[QuicSpdySession::OnNewEncryptionKeyAvailable / SendInitialData](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/http/quic_spdy_session.cc)
stage SETTINGS under a `ScopedPacketFlusher`.
[QuicSendControlStream](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/http/quic_send_control_stream.cc)
includes the stream type and reserved frame in that scope.
Only afterward does
[QuicChromiumClientSession::OnNewEncryptionKeyAvailable](https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_chromium_client_session.cc)
run the early-ready callback that admits the request. A blocked send may buffer
data; this is a send opportunity, not a guarantee of two UDP packets.

The captured snapshot's [158.0.8127.0 DEPS](https://github.com/chromium/chromium/blob/158.0.8127.0/DEPS)
pins the same QUICHE revision. Its `OnNewEncryptionKeyAvailable` implementation
is byte-identical to 158.0.8127.18; the function hash is retained in the observations.

Firefox 160's
[Http3Connection initialization](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-http3/src/connection.rs)
creates control/encoder/decoder streams and queues their initial state before
transport output. Eager QPACK type bytes are prepared together, rather than
scheduled by competing writers. In
[Neqo's output loop](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs),
the final Initial may share a datagram with a small protected early packet.
An Initial with more queued Initial CRYPTO ends the datagram instead. Packet
builders use the remaining capacity; Go's separate 128-byte packet/STREAM
heuristics are not equivalent to that rule.

[Neqo's SendStreams::write_frames](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/send_stream.rs)
services ordinary, non-fair HTTP/3 streams in creation order. WebTransport's
fair/send-group path is a separate mechanism. An earlier quiescent stream keeps
its place; credit-blocked streams do not starve later writable streams.
[Http3Session::SendData](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http3Session.cpp)
stages transaction data before `ProcessOutput`, including the bodyless FIN from
[Http3Stream::ReadSegments](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http3Stream.cpp).

## Reproduction and observations

The native reference is Chromium 158.0.8127.0 snapshot 1727489 on macOS arm64.
Ordinary `no-cors`, credentials-omitted GETs retain one about:blank document and
network context. Two warm requests are followed by two 45-second idle periods.
Certificate checks remain enabled. Original NetLog UDP payloads are reconstructed
with `tests/tools/echresumption/netlog.mjs` and independently decrypted by
Wireshark 4.6.9. Synthetic IP/UDP envelopes establish bytes, not NIC timing.

Surf repeats that sequence on the same Mac. The public API selects the Mac
profile and Fetch scenario, then replays the native regular fields using
`g.MapOrd`. The method, path, field values and order match. The public ECHConfig
from the native HTTPS lookup is supplied through TLSConfig so resolver timing
cannot change the compared handshake. Other TLS verification remains enabled.
Qlogs record actual serialized frames. Library profile identity defaults are
unchanged by this experiment.

Before the fix, those two Surf resumptions used two and one early packets:
SETTINGS could merge with the request. The updated Chrome profile gives initial
SETTINGS their own send opportunity before admitting the request. Both final Mac
resumptions use a control-only early packet followed by PRIORITY_UPDATE and
HEADERS+FIN, as in the native samples. Reserved-frame sizes can differ because
GREASE is generated afresh.

Firefox 160 is also run on the same Mac, using ordinary same-origin DOM fetches
and its diagnostic `network.http.http3.enable_qlog` preference. Its retained early
packets contain control data: a small prefix coalesces with the final Initial,
then the remainder and QPACK type bytes follow. The corrected Surf profile
preserves this layout and creation order while allowing an eligible API GET.
The native samples do not establish accepted early request data, so full Firefox
request-scheduling or packet-count parity is not claimed. The DOM/referrer
context still differs from the standalone API fetch.

A [later Firefox 160 capture](firefox_160/README.md) confirms accepted early GETs
in ordinary opaque Google fetches, including independently verified TLS Finished
and dynamic QPACK decoding. Those resumptions do not use real ECH. A separate
fresh Cloudflare transcript confirms accepted ECH plus control-only early data;
combined native ECH+early-GET acceptance and matching Surf packet scheduling are
still separate evidence gaps. The earlier control-only samples remain valid for
their original scenario.

A final independent Linux eth0 capture contains **175 captured packets, 175
reported by the filter and zero kernel drops**. Three fresh connections per
profile include four resumed connections. The existing transcript verifier
authenticates accepted ECH, selected PSK and accepted early request data for all
four resumptions. Each has two decrypted early packets, both with control data
and one with request data. This count describes these inputs only.

The two native Chromium request-stream payloads are **byte-identical** to the
corresponding independently decrypted Surf Linux payloads: 331 bytes each, with
hashes recorded in `request_block_comparison`. They include the actual HEADERS
frame/QPACK bytes, rather than just a normalized header fingerprint. Natural
idle expiry, exact native fields and the native ECHConfig distinguish this audit
from the previous opaque-Mac-fetch versus Linux-navigation comparison.

The public choices used by the profiles remain ordinary builders:

```go
builder.Impersonate().Chrome() // selects the Chrome early-settings boundary
builder.HTTP3Settings().EarlyData(true).Set()

// A custom HTTP/3 client can choose that boundary explicitly:
builder.HTTP3Settings().CoalesceInitialSettings(true).
    FlushEarlySettings(true).EarlyData(true).Set()
```

Early data remains opt-in. Unsafe methods/bodies retain verified-handshake
constraints. Raw transport controls are also available through QUICSettings:
`OnEarlyDataReady`, `FlushEarlyData`, `CoalesceSmallEarlyPackets`,
`InitialCryptoCoalescingBarrier` and `StreamSchedulingByCreation`.
Creation-order mode takes precedence over urgency/incremental scheduling;
disable it explicitly when an application wants the latter.

## Regression coverage and limits

[The verified TLS wire matrix](../../../http3_early_settings_test.go) gates the
resumed ServerHello on a real encrypted early request, avoiding scheduler sleeps.
It checks Chrome/Firefox and a custom client, ordinary and oversized control
data, callback chaining, frozen builders, eager stream order and bodyless FIN.
An independent interval oracle detects holes in Initial CRYPTO; datagram checksums
distinguish separate Chrome setup from Firefox's final-Initial coalescing. A
native-valid fixed DCID in that controlled test leaves a reproducible small tail;
the public browser profiles retain their real factories.

Private-engine tests additionally cover header-protection bounds for all packet
number widths, v1/v2 ticket versions, unchanged ACK/1-RTT thresholds, a real
STREAM in a small tail, pacing and queue limits, serialization errors, stream
creation versus publication order, quiescence, flow-control blocking, lost
ranges, completion cleanup and rejected 0-RTT state. Existing acceptance,
rejection/restart, 425, unsafe-body, cancellation, header ordering and recovery
suites remain part of full race-enabled verification.

All browser selections stay in Surf. The existing QUIC fork provides optional
generic mechanisms; default/nil behavior retains native scheduling. No TLS fork
changes, new forks, forced delays, anti-bot outcomes, native NIC pacing parity or
complete browser resource scheduling are implied by these results.
