# Firefox multi-space PTO datagrams

Firefox 160 Neqo spends two UDP datagrams per PTO, with a single cumulative
2×MTU retransmission-selection budget across Initial, Handshake and Application
spaces. Due spaces release recovery tokens; other timed spaces may contribute
PING. All spaces are examined before one backoff increment. After a crypto-space
packet, an empty follow-up PING is suppressed there. Application may still probe.

Primary sources are the pinned [recovery implementation](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/recovery/mod.rs)
and [connection output](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs).
Crypto ACK-only packets establish missing timer baselines. An Initial PTO primes
an empty Handshake baseline only with real Handshake keys and a prior Initial
ACK. New ACKs clear Firefox's backoff before address validation completes.
Retiring crypto keys and Retry discard the active budget; rejecting early data
retains the crypto PTO state.

The generic engine options are exposed through Surf's fluent
`QUICSettings().CoalescePTOProbes(true).InitialACKResetsPTO(true)`. Firefox enables
both; Chrome leaves both disabled. No browser constants are embedded in the
engine. Unconfigured clients and servers retain their native behavior.

## Independent references

`native.json` retains an official Linux arm64 Firefox 160.0 PTO event. Controlled
network admission drops Initial responses for 600 ms on a candidate offering
0-RTT, with a 75 ms Initial grace and a slower TCP path. Certificate verification
and ordinary HTTPS/QUIC racing remain enabled. The browser's recovery qlog
reports PTO at 222.229 ms. Independent TShark 4.6.9 decryption confirms Initial
PN14 in one datagram and Initial PN15 + 0-RTT PN6 PING in the second. This
candidate later loses its HTTP race; successful page fetches do not establish
that this particular connection completed or that its early data was accepted.

`surf.json` matches exact original encrypted UDP payload CRC32C values to Surf's
qlog and independently decodes them with TShark. The trusted local TLS/UDP peer
accepts resumed early data, delays its handshake until PTO is observed, and
completes the request on connection two. Explicit opt-out emits Initial-only
probes; the Firefox profile coalesces Initial and early Application packets.
Normal fresh application writes after PTO are not classified as probes.
All 71 packets in the capture were recorded without kernel drops. Raw captures,
traffic secrets, ticket values and browser profiles remain private.

## Regression scope

Handler tests cover all three spaces, shared byte and datagram budgets, future
armed spaces, Handshake-triggered Initial recovery, ACK-only baselines, key
retirement, Retry, rejection, ACK backoff and key-gated timer priming. Packer
tests cover v1/v2, forced ACK-only PING, ACK truncation, remaining Initial CRYPTO
priority, early-data coalescing and transient policy cleanup. The actual Surf
UDP test passes repeated race runs, including explicit opt-out. The complete
engine and Surf race/vet suites remain part of the gate.

This stage closes shared PTO batching, not peer-triggered early STREAM recovery,
complete migration behavior or OS packet-pacing parity.
