# STREAM recovery across packet copies

The generic QUIC mechanism tracks acknowledged byte ranges and FIN independently
of packetization. An original packet remains ACKable after a PTO schedules a
copy. An ACK of either transmission removes overlapping queued copies, including
split frames, and retires satisfied live frame accounting exactly once. Real
loss still updates congestion/bytes-in-flight once; its immutable STREAM ACK
metadata remains separately available for a late original ACK.

Browser policy stays in Surf's fluent profiles:

- `QUICSettings().StreamDataRecovery(true)` enables the mechanism.
- `StreamLossRetention(policy)` selects lost-packet metadata lifetime. It applies
  when STREAM recovery is enabled; nil retains useful metadata up to the existing
  engine packet limit. The callback receives measurements and must not block or
  reenter QUIC.
- Chromium keeps regular-loss metadata until an ACK reaches the next packet
  number after loss declaration. Firefox uses the current backed-off PTO period.
  Shared and separate packet-number domains remain distinct.

Both desktop profiles enable these settings. Generic QUIC clients and servers
retain upstream recovery unless explicitly configured. This change targets
STREAM data; unrelated control-frame callbacks keep their native behavior.

## Primary sources

- [Chromium STREAM send buffer](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_stream_send_buffer_inlining.cc):
  acknowledged intervals are subtracted from pending retransmissions; subsequent
  loss notifications exclude already acknowledged bytes.
- [Chromium sent manager](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_sent_packet_manager.cc)
  and [unacked map](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_unacked_packet_map.cc):
  ordinary loss records the next packet-number boundary for metadata retirement.
- [Firefox STREAM range tracking](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/send_stream.rs),
  [retained packets](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/recovery/sent.rs)
  and [recovery cleanup](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/recovery/mod.rs):
  PTO releases recovery tokens once without declaring the original lost; lost
  packets remain available for ACK processing until cleanup.

## Independent native references

`native.json` records three Firefox 160.0 anchors and one Chromium 158.0.8127.0
anchor. A privileged, isolated Linux network namespace delays two selected
outgoing short-header UDP datagrams per flow for 500 ms, while passing later
packets. Firefox delays the first two; the Chromium retained sample delays later
packets after four short-header datagrams. This is a network test condition.
Browsers keep normal certificate checks and ordinary public HTTPS discovery.
No forced QUIC, certificate bypass or User-Agent override is used. Firefox qlog
is diagnostic; Chromium uses its container-required `--no-sandbox`.

The executables are official Firefox Linux arm64 and Chromium snapshot 1727495
under Linux x64 emulation. The references show overlapping STREAM transmissions
before a late ACK of a delayed original, with no subsequent retransmission of
that acknowledged range. The anchors primarily cover HTTP/3 control/QPACK
streams. They do not establish complete browser upload or packet timing parity.

Original NIC captures have zero kernel drops. Wireshark 4.6.9 independently
decrypts exact encrypted UDP payloads captured at NFQUEUE, combined with original
captured server packets. Analysis IP/UDP envelopes are synthetic. Original and
analysis file hashes are retained; keys, raw captures, profiles and ticket data
remain private.

## Engine and Surf regressions

`quic-go/tests/stream_recovery_test.go` delays an original request-data STREAM,
drops its copy, then delivers the unchanged original through real UDP. It checks
PTO and actual-loss paths in shared and separate packet-number spaces, verified
TLS, exact response data and no STREAM transmission after the original ACK.
Fresh DATAGRAMs then advance ACKs beyond the discarded copy, exercising its loss.
The fixture uses explicit CIDs and a compact X25519 ClientHello to isolate this
STREAM test from first-flight layout/reassembly. Browser TLS templates are
checked separately and are not changed by this fixture.

`engine.json` independently decodes all 71 recorded client packets across these
four scenarios. Repeated closing datagrams are identified explicitly. Delivered
packets use NIC timestamps; discarded copies use logging timestamps. The
analysis is a decryption/range reference, not an OS pacing reference.

Unit regressions cover split-copy ACKs, partial ACKs and late real-loss ACKs,
FIN-only retransmission, duplicate notifications, coalescing queued ranges,
62-bit offsets, RESET_STREAM_AT, cancellation and epoch shutdown. ACK-handler
tests cover exact flight accounting, PTO reset, expiry, number-domain isolation,
Retry and rejection. Surf tests exercise policy boundaries and public opt-out;
its existing verified HTTP/3 loss tests exercise both fluent browser profiles
with complete POST bodies. Header and ticket suites remain part of full runs.

This closes the STREAM-copy mechanism scope. Subsequent stages verify
[shared PTO batching](../pto_batch/README.md) and
[peer-triggered early-data recovery](../early_peer_recovery/README.md). Complete
congestion/migration/timing parity remains separate verification work.
