# Initial CRYPTO recovery and HelloRetryRequest

`native.json` retains fourteen independent native cases: Firefox 160.0 and
Chromium 158.0.8127.0, each with an ordinary first flight, whole-flight loss,
partial first-flight loss, HRR, HRR plus whole-flight loss, HRR plus partial loss,
and loss of the second ClientHello. Each public ClientHello is hashed; no TLS
ticket identity is admitted to this fixture. Dynamic keys and raw browser
profiles remain private in `/tmp/surf-initial-recovery-audit`.

## Capture method and limits

Visible browsers use fresh isolated profiles, ordinary HTTPS discovery and their
normal protocol/TLS policy. The disposable network namespace redirects UDP/443
to a controlled alternate QUIC peer and delays outbound TCP/443 by 750 ms so a
TCP backup does not obscure the Initial exchange. The server requests HRR by
selecting P-384. Its certificate is deliberately untrusted: both browsers retain
certificate verification and reject it after the captured ClientHello exchange.
These are native pre-certificate Initial/HRR references, not successful native H3
application sessions. No forced QUIC, certificate bypass, custom resolver or
User-Agent override is used.

Firefox runs natively on Linux arm64 under Xvfb. Chromium is the official
Linux_x64 snapshot 1727495 under amd64 emulation and Xvfb. Chromium's container
requires `--no-sandbox`; this does not bypass TLS verification. Its retained
connections are ordinary background `www.google.com` traffic, not asserted to be
successful navigations to the Firefox target `fp.impersonate.pro`.

NIC captures retain their actual provenance and GSO limitations. Exact UDP
datagrams are separately recorded at the controlled socket. Analysis wraps those
unchanged payloads in synthetic IP/UDP envelopes to avoid interpreting a GSO
aggregate as one datagram. Wireshark independently confirms every retained packet
number and CRYPTO offset, length and order against the RFC Initial decoder.
Synthetic envelopes and emulated execution do not establish OS timing parity.

## Source mapping and changes

- [Neqo CryptoStreams::write_frame](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/crypto.rs)
  chooses the next eligible byte range, rather than replaying old frame boundaries.
  SNI slicing applies only at absolute stream offset zero and when that available
  prefix contains the complete SNI. Adjacent lost ranges coalesce; gaps remain.
- [Neqo recovery](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/recovery/mod.rs)
  prepares up to two original packets before constructing Initial PTO probes.
  The original packet can still be acknowledged after a probe is scheduled.
- [Neqo peer-probe handling](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs)
  reschedules sent, unacknowledged Initial data on PING or non-progressing CRYPTO.
  A duplicate HRR can therefore prompt CH2 recovery before its own PTO.
- [QUICHE PTO allowance](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_sent_packet_manager.cc)
  selects one probe, and
  [QuicConnection::OnRetransmissionTimeout](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_connection.cc)
  skips one number at PTO. Native whole-flight examples use Initial 1, 2, 4, 5.
- [QUICHE crypto send buffer](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/quic_crypto_stream.cc)
  excludes acknowledged bytes from later copies. Chrome's packet-local Chaos
  Protection still randomizes its frame layout; exact randomized bytes are not
  treated as a deterministic golden encoder output.

The existing QUIC fork now offers optional byte-range Initial recovery, original
PTO ACK retention, live-budget recovery layouts, an Initial probe allowance,
number skipping and peer-probe response. Browser constants and decisions live
only in Surf's fluent profiles. Nil/default engine controls retain upstream
behavior. Full Initial transcript storage is released when Initial keys retire.
HRR keeps the Initial stream offset: Firefox CH2 is one sequential nonzero-offset
range, while Chrome retains its packet-local protection. The TLS engine was not
modified for this work.

The public controls are ordinary `QUICSettings()` chain methods:
`InitialCryptoRecovery`, `InitialCryptoRecoveryLayout`,
`InitialCryptoProbePackets`, `InitialProbeSkipPacketNumber` and
`InitialCryptoResendOnPeerProbe`. Chrome and Firefox install their defaults; an
application does not need a separate activation flag. The profile code itself is
the example of composing these controls.

## Regression checks

- Native Firefox references replay both original and recovered ranges with each
  captured packet's actual frame budget. HRR and its lost copy retain CH2 offsets.
- Actual encrypted UDP peers exercise both Surf profiles with no loss, partial
  loss, whole-flight loss and loss of CH2, with and without HRR: fourteen cases.
  The suite reassembles the complete TLS messages, rejects changed bytes in any
  copy, and compares decrypted Firefox recovery order to the selected source
  policy. This timer-layout matrix disables Firefox peer-triggered recovery so
  an unacknowledged CH1 replay cannot stand in for the CH2 timer probe. Separate
  peer-recovery suites keep the complete browser policy enabled. Whole-flight
  tests also check Chromium's Initial number gap.
- Engine tests cover coalescing, holes, duplicate losses, partial ACKs, late ACK
  of the original PTO packet through the real ACK handler, bounded probe counts,
  exhausted peer-validation state, invalid plans, HRR offsets, exclusion of
  unsent/ACKed bytes and key-retirement cleanup. A byte-by-byte oracle checks
  randomized interval operations.

Validation results and capture hashes are in `validation.json`.

## Remaining scope

This audit covers the described Initial exchanges. Later Handshake/Application PTO controls and missing-key hints are covered by
the [next audit](../pto_recovery/README.md). Native accepted application sessions
under every loss pattern, complete recovery/congestion behavior and OS scheduling
remain separate scopes in [BROWSER_PARITY.md](../../../../BROWSER_PARITY.md).
