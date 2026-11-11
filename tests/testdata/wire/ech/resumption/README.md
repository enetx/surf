# Native ECH resumption and early-data references

Captured on 2026-11-11 with official Chrome 157.0.8103.51 on macOS arm64 and
official Firefox 160.0 on Linux aarch64. Browsers used fresh isolated profiles,
ordinary Cloudflare Secure DNS preferences, and normal certificate verification.
No TLS, ECH, cipher, QUIC or certificate bypass flags were used.

| Native reference | Pairs | Outer PSK          | Server accepted early data | Decrypted early packets / control / request |
| ---------------- | ----: | ------------------ | -------------------------- | ------------------------------------------- |
| Chrome TCP       |     2 | omitted            | no offer                   | 0 / 0 / 0                                   |
| Chrome QUIC      |     2 | omitted            | yes                        | 2 / 2 / 1 each                              |
| Firefox TCP      |     1 | randomized framing | no offer                   | 0 / 0 / 0                                   |
| Firefox QUIC     |     1 | randomized framing | yes                        | 2 / 2 / 0                                   |

The `surf/` references come from real tcpdump captures of the fluent
probe in `tests/tools/echresumption`. The original 12 connections used verified
ECH and the eight repeated handshakes resumed. Chrome QUIC was subsequently
recaptured with cached RTT: all three connections used verified ECH and both
repeated handshakes resumed. Four second-handshake pairs are retained.
Chrome QUIC sent 2 early packets (2 carrying control data, 1 carrying a request);
Firefox QUIC sent 5 (3 carrying control data, 1 carrying a request). Counts refer
to QUIC packets, may overlap, and include retransmissions. They are observations
of these connections, not fixed browser packet-count prescriptions.

## Verification and privacy

Each pair includes the actual expanded inner, the corresponding wire outer and
ServerHello, and evidence that the server selected PSK identity zero. The capture
tool verifies the RFC 9849 section 6.1.4 ECH acceptance confirmation against the
**original** inner transcript before writing a reference. It also verifies the
selected cipher's binder length, matching session IDs, TLS 1.3 selection, outer
PSK framing, and absence of the private identity from the outer.

All PSK identities, ages, binders and legacy session-ticket payloads are zeroed
before publication. Lengths/order and unrelated bytes remain unchanged. The
original confirmation transcript hash is retained so offline tests can check
the recorded authenticator. That digest is explicitly for the original private
capture: recomputing it over the masked ClientHello must **not** succeed.
The generation-time check binds the original message; the sanitized file alone
does not allow reconstruction of its removed PSK bytes.

Only EncryptedExtensions IDs are retained. Its actual early-data extension is
checked separately from NewSessionTicket's extension of the same number.
Raw server transport parameters can contain stateless-reset tokens and are not
published. No private traffic secrets, usable tickets, pcaps, complete NetLogs
or browser profiles belong in this directory.

## Capture details and limits

Chrome's expanded inner comes from native `SSL_ENCRYPTED_CLIENT_HELLO`. TCP
outer/server messages come from the same NetLog source. QUIC server messages
come from conflict-checked CRYPTO reassembly; Wireshark independently reassembles
the outer from captured UDP payloads. The UDP socket is identified by matching
Initial DCID, **not** the QUIC pool-job `source_dependency`.

For TCP, Chrome's built-in socket-pool flush retains the TLS session cache;
Firefox uses normal `location.reload(true)`. For QUIC both browsers use natural
idle expiry. The Firefox reference uses stock NSS ECH key-log records and
Wireshark 4.6.9 to decrypt/expand the inner. Firefox TCP had other connection
attempts; only the complete, authenticated ECH/PSK pair is retained.

Original input hashes are recorded in each file. Chrome QUIC's analysis pcap
uses the actual NetLog UDP payloads inside synthetic IPv4/UDP envelopes. Firefox
QUIC required segmentation of five GSO aggregates in an **analysis copy**;
Initial AEAD authentication and CRYPTO reassembly verified the segment cuts.
Neither method establishes NIC datagram boundaries, IP headers or pacing.
The separate Surf capture disabled offloads in its isolated container and had
zero kernel capture drops; its original pcap is retained privately.

ECH engines/key-log analyzers can index secrets by the outer or inner random.
The analysis tool preserves original logs and adds lookup aliases with unchanged
secret material. This was needed to decrypt native and Surf early packets.
TShark extraction uses `--no-duplicate-keys`, retains coalesced packet objects,
and reads raw STREAM payload length when a STREAM frame omits its LEN field.

The accepted Firefox QUIC reference has control-only early data. A follow-up
native same-origin fetch capture also sent request stream zero in 0-RTT, but
completion of that connection was not established and it is not an accepted
reference. Firefox's safe-method source policy allows early GET requests; this
sample does not justify forcing all Firefox requests to wait for 1-RTT.

## Comparison result

`tests/profiles/ech/inner_test.go` checks the complete cipher/extension bytes and
order by applying Surf's callback to each of the six native outer messages.
The engine appends its own final PSK; callbacks cannot supply live binders.

Independent comparisons of actual Surf/native inner messages preserve cipher
and group order, extension presence, opaque fixed payloads, PSK lengths and QUIC
parameter encodings. Only connection randoms, key bytes, ticket bytes, GREASE,
measured RTT with its resulting minimal integer width, and source-confirmed
permutations are normalized. Chrome permutes TLS/QUIC
parameter/version order; Firefox QUIC permutes TLS extensions, while Firefox
TCP and Firefox QUIC parameter/version order remain ordered.

Chrome and Firefox TCP/QUIC stable inner features match the retained native
references. Chrome QUIC now advertises measured `initial_round_trip_time_us`
(`0x3127`) when this client has direct-connection history for the origin.
The previous exception for a missing parameter has been removed: conformance
compares all features. Presence and minimal encoding remain significant while
the observed RTT and consequent integer width vary with the network.
See [cached RTT source checks and tests](RTT.md). Disk persistence remains separate.

These references establish ECH/PSK/early-data properties, not complete browser
packet, scheduling, OS, fresh-handshake, HRR or rejection-path parity. Existing
local tests independently cover HRR, SHA-256/SHA-384 binders, retry limits,
certificate failures, ALPN/session veto and 425 replay behavior.

## Pinned sources

- [RFC 9849 ECH confirmation](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4),
  [RFC 8446 PSK framing](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11).
- [Chrome 157 BoringSSL ECH/PSK extensions](https://github.com/google/boringssl/blob/5b83e5d1abf0ae0033ae52ab579d906b67633b2c/ssl/extensions.cc).
- [Chrome 157 socket-pool flush and separate TLS-cache clearing](https://chromium.googlesource.com/chromium/src/+/157.0.8103.51/net/http/http_network_session.cc).
- [Pinned QUICHE RTT transport parameter](https://github.com/google/quiche/blob/541aa2a7889b7ea7651e41afc58211f2a256850a/quiche/quic/core/crypto/transport_parameters.cc#L90).
- [Firefox 160 NSS ECH construction](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13ech.c).
- [Firefox 160 QUIC TLS extension permutation](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/nss-rs/src/agent.rs#L448).
- [Firefox 160 safe-method early-data policy](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp#L3529).
