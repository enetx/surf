# Firefox peer-triggered early STREAM recovery

The pinned Firefox 160 [connection implementation](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/connection/mod.rs)
resends early data when a routed Handshake/short packet arrives before Initial
keys can establish TLS, within the saved-datagram limit. Authenticated Initial
CRYPTO with no newly contiguous input also resends early data. PING resends
CRYPTO only. The [recovery implementation](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/third_party/rust/neqo-transport/src/recovery/mod.rs)
removes outstanding early packet accounting without declaring congestion loss;
a new Application ACK permanently disables this hint mechanism.

Surf's Firefox profile enables `EarlyDataResendOnPeerCrypto(true)` and returns
`PeerPacketRecovery{ResendEarlyData: true}` alongside eligible Initial hints.
The public fluent method and public policy/action types remain available for
custom configuration. Chrome leaves this Firefox mechanism disabled. There is
no new transport, TLS-verification override or implicit browser flag.

Generic engine removal schedules recovery tokens once per discarded packet,
releases flight bytes once and preserves crypto PTO state. Repeated hints before
new transmission do not duplicate tokens. Retired original packets no longer
own late-ACK tokens, unlike normal PTO copies. A late ACK of separately retained
actual-loss metadata also ends the mechanism. TLS rejection remains the distinct
same-connection HTTP/3 restart described in `../early_rejection/`.

## Native and local evidence

`native.json` independently decrypts the resumed Firefox 160 candidate retained
in `../pto_batch/native.json`: STREAM 2 bytes 0–15 appear in early PN0, then
PN2 and PN4 at 55.297/60.826 ms, before its first PTO at 222.229 ms. Browser qlog
also records removal of early flight bytes. This is a control-stream reference
on a racing candidate; it does not establish native upload or request completion.

`surf.json` independently checks exact UDP CRC32C, early packet numbers and STREAM
ranges with TShark 4.6.9 and a separate RFC 9001 HKDF/AES-128-GCM decoder. All 301
recorded early packets authenticate. The latter also handles standalone 0-RTT
CID association that Wireshark misses after a withheld Initial. Analysis includes
withheld original Initial payloads in synthetic envelopes, with pre-admission
logging timestamps; these packets were not delivered to the browser. It is not
a NIC pacing reference. The peer uses verified TLS, a warm ticket and accepted
0-RTT. A controlled packet gate withholds server Initial packets but preserves
unchanged Handshake payloads even when the server coalesces them with Initial.
The Firefox profile repeats STREAM bytes before its first PTO; explicit opt-out
waits for PTO. Both requests complete on the second connection. The gate recognizes negotiated fixed-bit GREASE in v1/v2. The fixture disables
learned/ticket-restored loopback RTT and the separate backup attempt, and uses a 300 ms initial estimate so race instrumentation
does not expire PTO before peer hints can arrive. It is not a reference for
native timing or server datagram composition. Traffic secrets, raw captures and ticket values remain private.

Unit checks cover missing keys versus bad MAC/retired keys, Initial input with
and without progress, Handshake input, PING, rejection, completed TLS, server
role, nil policy, opt-out, duplicate hints, shared/separate number domains,
flight accounting, congestion window and PTO preservation, and live/retained
Application ACKs. Complete engine/Surf race and vet suites cover interaction
with stream-copy ACK tracking, rejected 0-RTT restart, tickets and headers.
