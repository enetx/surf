# Early data during connection racing

Browser policy is configured through Surf's public fluent builder. The existing
QUIC fork adds `Transport.PreconnectEarly`, returning the pooled connection when
cached early keys become available. `Preconnect` retains its verified-handshake
contract. Neither API sends an HTTP request; early readiness does not authenticate
the current handshake. Cold connections still wait for a completed handshake.

## Pinned source checks

- [Chrome 157 CryptoConnect](https://github.com/chromium/chromium/blob/157.0.8103.51/net/quic/quic_chromium_client_session.cc#L1644)
  permits session activation when encryption is established without requiring
  handshake confirmation. Recently broken/stale attempts require confirmation
  in [QuicSessionAttempt](https://github.com/chromium/chromium/blob/157.0.8103.51/net/quic/quic_session_attempt.cc#L227).
- [Firefox 160 Http3Session](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http3Session.cpp#L1491)
  starts the transaction backup timer before confirmation; eligible transactions
  can enter its 0-RTT stream list. A ready TCP backup can restart a transaction
  until it is connected in [OnBackupConnectionReady](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp#L3935).
- Firefox's [ZeroRttHandle](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/ZeroRttHandle.cpp)
  requires an actual owned safe transaction, retains attempt-local read offsets,
  and adopts the winner on completion. Speculative preparation without a real
  transaction may send control streams without a request. The new Surf path
  owns one bodyless GET/HEAD and keeps its cancellation independent of other
  callers sharing the connection pool.

The profile sets `EarlyDataBackup(false)` for Chrome and `true` for Firefox.
`EarlyData(true)` and a session cache are still required. POST, GET with a body
and other ineligible methods use full-handshake selection. Separate preparation
flights prevent an early-ready caller from committing an unsafe caller.
Firefox's early request is canceled when TCP wins; any unselected response body
is closed. A selected response retains its context until its body closes.

Address preparation can select an early-ready candidate. Pending candidates are
canceled and successful losers close; one address owns the request. Browser
profiles retain their existing address-staggering defaults. This API does not
implement the browser's entire multi-address/resource scheduler.

Coalesced SETTINGS setup is retained per candidate in the QUIC transport. The
old single setup callback could bind HTTP/3 to a losing candidate when a custom
dialer prepared multiple connections. A regression fails with that code and
passes after binding setup to the returned connection. Temporary candidate
references are released after dial finishes.

## Capture observations

The public probe used normal certificate verification, ECH discovery, one TLS
cache per client, `EarlyData(true)` and `ConnectionRacing(true)`. All six Surf
connections negotiated HTTP/3 with verified ECH; four repeated connections
resumed. Wireshark independently decrypted an early request on each of those
four connections. Original ECH acceptance confirmations and PSK selection were
also independently verified before redaction. Packet counts vary with scheduling.
The original tcpdump contains 146/146 captured packets and zero kernel drops;
capture shutdown allowed two seconds for the receive buffer to drain.

Fresh ordinary Chrome 157 and Firefox 160 navigation also exercised both H2 and
H3 outcomes after idle expiry, with verified ECH and no protocol/certificate
bypass flags. Firefox's completed resumed H3 observation had two control-only
early packets. Its diagnostic log showed a speculative attempt checking early
eligibility before the real transaction was claimed; that observation is not
a rule forbidding early Firefox GETs. A later attempt under an isolated 1-second
UDP egress delay completed over H2. It did not offer early data, so it is not
claimed as a native early-request takeover capture.

Five Firefox UDP GSO aggregates were split at the source-confirmed 1252-byte
segment boundary in an analysis copy. Wireshark authenticated Initial packets
and reassembled the messages. These are TLS/frame observations; synthetic segment
envelopes and capture before the Linux qdisc do not establish NIC packet timing.
No private keys, usable PSKs, raw captures, NetLogs or browser profiles are stored
in this repository. `observations.json` retains sanitized evidence and source pins.

## Regression checks

Tests gate the resumed ServerHello until an eligible early packet is emitted,
then check Chrome's early commitment and Firefox's retained TCP backup separately.
They cover cold/TCP wins, POST exclusion, cancellation, accepted/rejected early
data, bounded 425 replay, shared waiters, separate early/confirmed flights,
address advancement and cancellation, pooled reuse and per-candidate setup.
An older confirmed connection cannot erase a later failed attempt: a regression
checks that the next early-eligible caller still requires handshake confirmation.
Existing ECH, proxy, header ordering and fallback suites remain in the full run.

Reproduce the public Surf observation using the existing capture probe with
`-probe chrome|firefox -protocol h3 -early -racing -keylog NEW_PRIVATE_FILE`.
The probe requires H3, verified ECH and resumed repeated attempts; a legitimate
TCP race win makes that strict capture probe fail rather than claim H3 evidence.
