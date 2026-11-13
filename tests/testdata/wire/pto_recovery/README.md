# Handshake and Application PTO recovery

This stage adds independent Handshake and Application Data PTO allowances,
Handshake/Application number gaps, late original ACK tracking for Handshake CRYPTO, and
Firefox peer-probe responses. Browser values remain in Surf's fluent profiles;
the existing QUIC fork exposes mechanisms with native defaults. No TLS engine
changes or new forks are involved.

## Primary sources

- [Chromium 158 QUICHE sent packet manager](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_sent_packet_manager.cc):
  PTO grants one timer transmission; the oldest eligible packet supplies a copy.
- [QUICHE retransmission alarm](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_connection.cc):
  PTO skips one number before writing; it can send PING when data is unavailable.
  [Its packet creator](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_packet_creator.cc)
  increments ordinary numbers consecutively. Chrome disables the Go engine's
  random gaps while preserving its explicit PTO gap.
- [Firefox 160 Neqo recovery](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/recovery/mod.rs):
  a PTO has a two-datagram budget. Initial/Handshake stop forcing empty follow-up
  probes after the first packet; Application may use PING for its second packet.
  Original packet ACK metadata survives scheduling a probe copy.
- [Neqo connection input and maybe_probe](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs):
  PING immediately requests ACK and reschedules unacknowledged CRYPTO. Useless
  Initial CRYPTO can also reschedule Handshake bytes. Routed Handshake/short
  packets while waiting for the first authenticated Initial can prompt Initial
  recovery. A retired Initial before TLS completion can prompt Handshake PING.
- [Neqo saved datagrams](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/saved.rs):
  either four-entry saved store stops missing-Initial hints. Surf's callback
  checks both available engine buffer counts before responding.

## Independent native evidence

`native.json` retains seven sanitized flows: Chromium 158.0.8127.0 and Firefox
160.0 with no injected loss, Handshake loss and Application loss, plus Firefox
receiving Handshake packets while the server's Initials are dropped. Retained
fields are numbers, ranges, frame types, timestamps and file hashes; TLS keys,
ticket identities, bodies, raw captures and browser profiles are not committed.

Visible browsers use fresh isolated profiles and ordinary public HTTPS discovery.
NFQUEUE drops outgoing UDP datagrams whose first packet has the selected level
for 800 ms; coalesced packets share that verdict. The missing-Initial experiment
instead drops incoming Initial datagrams for 500 ms. Both browsers keep their
normal certificate validation. No forced QUIC, custom resolver, TLS bypass or
User-Agent override is used. Chromium is official snapshot 1727495 on emulated
Linux x64 with the container's required `--no-sandbox`. Firefox is the official
Linux arm64 executable under Xvfb; its reported Linux UA contains x86_64 and was
not overridden.

The retained Chromium flows are background `www.google.com` connections; they
are not represented as successful navigations to the Firefox target. Ordinary
Firefox document observations report H3 at `fp.impersonate.pro`. The missing-key
reference is a v1 background `push.services.mozilla.com` connection. v1/v2-switching
flows whose offline decoder inferred a lost version switch are excluded from
that missing-key golden.

Original NIC captures have zero kernel capture drops. Wireshark 4.6.9 decrypts
using private TLS key logs. Loss experiments also retain exact client datagrams
at the queue hook: dropped packets cannot appear on the physical interface.
The first six analysis PCAPs combine original captured server packets with those
unchanged client payloads in synthetic IP/UDP envelopes. The missing-Initial
analysis instead retains exact queued raw IP packets with an arbitrary time
origin. Neither analysis establishes OS pacing parity.

Chromium examples show Handshake 4 -> 6 and Application 13 -> 15 / 16 -> 18.
Firefox examples keep contiguous numbers and a close pair of Application probes
4/5, with PING in the second packet. The missing-Initial native example resends
CRYPTO promptly after Handshake arrival, before the original Initial PTO.
Individual retransmissions may also be peer-triggered; spacing alone is not used
to classify every packet as a timer probe. Primary-source budgets are tested
separately through the actual engine ACK handler.

## Surf API and tests

Profiles install defaults automatically. Public `QUICSettings()` methods are
`HandshakeCryptoRecovery`, `HandshakeCryptoResendOnPeerProbe`,
`HandshakeProbePackets`, `ApplicationProbePackets`,
`HandshakeProbeSkipPacketNumber`, `ApplicationProbeSkipPacketNumber`,
`HandshakeProbeOnlyWithData`,
`PeerPacketRecoveryPolicy` and `ImmediateACKOnPeerPing`. Existing Initial and
Application random-number controls retain independent ownership. A native engine
config keeps its original combined random/PTO switch unless an explicit PTO
override is supplied. Setters and
fields have documentation comments; no additional configuration interface is
introduced.

- `quic_pto_spaces_test.go` executes verified TLS HTTP/3 connections for both
  profiles with Handshake and established Application loss. Full POST bodies
  must arrive unchanged, actual PTO events must occur and on-wire number gaps
  must follow the browser. The loss window starts at the first matching packet;
  the gate scans every packet in a coalesced datagram and accepts fixed-bit
  GREASE. A separate missing-Initial peer test checks the
  Firefox callback through real encrypted UDP and verified TLS.
- `quic_pto_native_test.go` checks independently retained native anchors, the
  contiguous Firefox Application pair and its pre-PTO Initial recovery hint.
- Engine regressions cover count 0/1/2 and gap controls in each later space,
  1,000 consecutive ordinary numbers followed by a deliberate PTO gap and
  skipped-ACK rejection, private cloning of the override, late original Handshake
  ACKs, key retirement, availability checks, coalescing
  repeated hints, ignored authentication failures and immediate PING ACK under
  native, explicit and negotiated legacy receive policies.

Run the focused Surf regressions from its module directory:

```sh
go test -race -count=10 ./tests -run 'PTORecoveryNativeReferences|BrowserHandshakeAndApplicationPTOOnWire|PeerRecoveryAndPTOFluentControls|FirefoxMissingInitialPeerHintOnWire'
```

A passive diagnostic overlay additionally records exact Surf UDP payloads and
private TLS keys. Wireshark independently checks every serialized client packet
type and number against qlog across all four loss scenarios. Small closing
datagrams that the peer has not read are retained directly from the NIC capture.
The overlay does not change production files or TLS verification.

`validation.json` records the original audit results and capture hashes. These
controls are published in `enetx/quic-go v1.0.23` and used by Surf `v1.0.237`;
normal module consumers do not need a local workspace or replacement.

## Remaining scope

This stage covers the recorded per-space cases. Subsequent stages verify
[STREAM-copy ACK relationships](../stream_recovery/README.md),
[shared PTO datagrams](../pto_batch/README.md), and
[peer-triggered early STREAM recovery](../early_peer_recovery/README.md).
Whole-session congestion evolution, every native loss pattern and OS scheduling
remain outside these references. See [BROWSER_PARITY.md](../../../../BROWSER_PARITY.md).
