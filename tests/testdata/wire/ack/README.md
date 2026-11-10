# Receive ACK policy — Chromium 156 and Firefox 160

Browser sources are pinned to Chromium 156.0.8078.79's Quiche
`a1628192cf32ba40d21e0dd80f485d68c24ff87a` and Firefox
`FIREFOX_160_0_RELEASE` (vendored Neqo).

| Default receive behavior | Chromium | Firefox |
| --- | --- | --- |
| Initial Application Data threshold | 2 ack-eliciting packets | 2 ack-eliciting packets |
| Decimation | Threshold 10 once current PN reaches smallest received PN + 100 | None by default |
| Delayed ACK deadline | Initially 25 ms; after transition `max(1 ms, min(25 ms, minRTT/4))` | 20 ms |
| Further arrivals | Keep earliest pending deadline | Keep first pending deadline |
| Gap behavior | Immediate ACKs for the first four packets after a gap; immediately ACK a previously reported missing packet | Immediately ACK an out-of-order ack-eliciting packet |
| ECN | Immediate ACK on transition to CE | Count ECN; no separate CE ACK trigger in `set_received` |
| Initial/Handshake spaces | Separate minimal-delay scheduling path (1 ms bound) | Immediate ACK |

The transition is a **packet-number span**, not the number of received packets.
Non-ack-eliciting packets contribute packet numbers but not the packets-per-ACK
counter. Decimation remains active after ACKs. Lost and reordered packets can
prompt earlier ACKs. The four-ACK gap window is separate from ACK decimation.
ACKs piggybacked on outgoing application traffic may also occur earlier.
Surf's new controls apply to Application Data only. Initial/Handshake retain
the native engine's immediate ACK path; their scheduling is not claimed to
match Chromium's separate minimal-delay path exactly.

Sources:
[QUICHE receive scheduling](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_received_packet_manager.cc),
[constants](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/quic_constants.h),
[default RTT fraction](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/common/quiche_protocol_flags_list.h),
[Initial/Handshake ACK policy](https://github.com/google/quiche/blob/a1628192cf32ba40d21e0dd80f485d68c24ff87a/quiche/quic/core/uber_received_packet_manager.cc),
[Neqo receive tracking](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/tracking.rs).
Neqo's [ackrate.rs](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/ackrate.rs)
requests acknowledgment behavior from the **peer**; its ratio must not be applied
to Firefox's local receive threshold. Negotiated ACK_FREQUENCY and optional
QUICHE AKD3/AKDU/1ACK options are outside the default policies above.

## Observed real browser traffic

`browser_observations.json` records a fresh local run with installed Chromium
156.0.8078.79 and Firefox 159.0.1, new isolated headless profiles, and a 2 MiB
response. It includes browser versions, timestamps, pcap SHA-256 and histograms
for browser, Surf preset, and Surf exact-input replay, over 1600 server packets
per connection. The peer observed and decrypted actual browser ACK frames.

| Client | Median newly acknowledged packets before span 100 | After span 100 |
| --- | --- | --- |
| Real Chromium | 2 | 10 |
| Surf Chrome preset | 2 | 10 |
| Surf Chrome exact-input replay | 2 | 10 |
| Real Firefox | 2 | 2 |
| Surf Firefox preset | 2 | 2 |
| Surf Firefox exact-input replay | 2 | 2 |

This validates the transition in this workload. It does **not** establish equal
full distributions, packet scheduling or timing. The histograms differ because
of buffering, piggybacked ACKs, tracing and scheduling. For example, the browser
Chromium run reported ACK delays up to 4.56 ms, despite the scheduling formula's
1 ms floor on loopback. Surf's maximum reported delays in this run were below
1 ms. Packetization, congestion and NIC-level timing remain separate work.

Raw packets, TLS keys and browser profiles are private temporary artifacts.
Only compact metadata and statistics are committed. Reproduce using the
[capture tool](../../../tools/wirecapture/README.md#ack-observations).

Surf selects these policies through fluent methods in each browser's
`profiles/*/quic/ack.go`; the QUIC fork exposes generic optional controls.
`ResetAckPolicy()` restores the native scheduler while retaining `MaxAckDelay`.
The implementation changes local ACK generation only. It does not advertise or
implement ACK_FREQUENCY or version negotiation. Native/server defaults remain
unchanged, and no additional dependency fork is introduced.
