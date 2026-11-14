# Linux QUIC bulk-transfer audit — 2026-11-14

`observations.json` contains sanitized results from real Linux ARM64 interface
captures: official **Google Chrome for Testing 158.0.8127.18**, Mozilla Firefox
160.0 and Surf. This Chrome reference is separately labeled from the unbranded
Chromium Mac references. Download URLs, binary/source hashes, Firefox build ID,
capture hashes and tcpdump counters are recorded. Raw pcaps, TLS keys and browser
profiles remain private.

## Cases and corrections

| Condition per direction | Bulk GET | Fixed POST echo | Streaming POST echo |
| --- | --- | --- | --- |
| Baseline | 32 MiB | 4 MiB | 4 MiB |
| 20 ms + 0.25% loss | 16 MiB | 4 MiB | 4 MiB |
| 10 ± 2 ms + 5% reordering | 4 MiB | 1 MiB | 1 MiB |

The public purpose-built peer is `quic.aiortc.org`: `/N` returns N ASCII `Z`
bytes and `/echo` returns the request body. Every accepted bulk result passes
size, status, HTTP/3 and SHA-256 checks. Firefox 160 supports the tested
ReadableStream Fetch request; the driver checks duplex support and rejects
coercion into a string. Google Storage supplies an additional verified 32 MiB
range reference with HTTP 206 and a fixed hash. No certificate bypass is used.

The audit found and corrected four runtime problems:

* **Chrome ACK flushing:** before the correction Surf's late ACK median/maximum
  was 14/41 newly observed eliciting packets. Corrected Surf and native Chrome
  both have 10/10; their early median is 2. Chromium flushes a pending response
  per datagram, including datagrams from one socket-read batch. The engine's
  32-datagram event-loop batch formerly postponed it. `AckFlushOnPacket` gives
  a queued ACK a send opportunity. Socket backpressure can still delay it.
* **Firefox packet-space snapshots:** PING-probe and packet-number policies now
  read the selected history when separate spaces are enabled. The former
  shared history was empty in that mode. Regressions cover 0-RTT/1-RTT packets,
  removed slots and path probes. Actual PING probes return in load captures;
  exact counts depend on RTT and batching.
* **Chrome intermediate elision:** Google Storage sends one leaf issued by WE2
  after receiving Trust Anchor IDs. Signed issuer candidates now complete the
  chain while configured/system roots retain authority. The same 186-byte
  extension matches native Chrome exactly. `chain-verification.json` records
  one peer certificate and a verified chain; a separate macOS system-root check
  also completed 32 MiB. Offline tests fix the verification time to the capture
  date and separately exercise invalid chains, root ownership and callbacks.
* **Retained TCP winner:** a completed TCP choice could outlive confirmation of
  QUIC in the other early/full slot. New requests now reconsider the usable QUIC
  connection without disturbing existing waiters. Deterministic and real TCP/UDP
  regressions pass 100 repeated Linux runs. First-use automatic H3 history is a
  separate scope.

Receive-credit updates follow the selected browser policies: roughly 3/7.5 MiB
stream/connection steps for Chrome, and 3/6 MiB for Firefox. Actual deltas are
retained. Repeated MAX_DATA probes do not count as additional receive credit.
The engine contains generic mechanisms; browser values remain in Surf.

## Header fidelity and excluded attempts

Surf replays captured ordered regular and pseudo fields through its configured
public transport, with an explicit H3 attempt and TCP racing disabled. This
isolates transport mechanics, not automatic discovery or complete browser history.

All Chrome pairs and final Firefox baseline/loss pairs match every bulk request
field and its order. The retained successful Firefox reordering transport run
still generated an extra `Alt-Used`. Native Fetch here uses `credentials: omit`,
and Firefox deliberately omits that header for anonymous requests. The current
exact replay disables automatic Alt-Used generation while preserving explicit
captured fields. Firefox's ordinary profile behavior is retained. The earlier
successful reordering pair is **not** labeled an exact header match.

Three subsequent cold Firefox replay attempts under reordering failed to
establish H3 and remain excluded from positive H3/header comparisons. The second
capture has outgoing Initial retransmissions and no UDP reply; the cause is
unestablished. An independent ordinary Firefox control initially used H2 twice,
then completed all three H3 bulk cases. It does not prove the same failure cause.
A larger Chromium reordering attempt exceeded the measurement deadline; the
accepted 4 MiB case is separate. These observations do not establish perfect
cold-start behavior on every impaired path.

## Capture and timing limits

These are Ethernet/veth packets in a Docker Linux VM, not synthetic test-server
envelopes or bare-metal NIC observations. Browsers run non-root with fresh
profiles, normal protocol/trust policy and automation/UI controls only. There
are no UA, certificate, protocol or field-trial overrides. GRO, GSO, TSO and UDP
segmentation are disabled. Accepted captures have zero kernel capture drops and
no snap-truncated records, independently checked before dissection.

The capture point precedes egress netem and ingress IFB effects. Captured spacing
and order are not necessarily socket-delivery spacing/order; a visible packet
can later be dropped by a qdisc. Netem drops differ from tcpdump drops. Public
path variation, VM scheduling and connection histories prevent treating transfer
durations as proof of benchmark or pacing parity.

ACK analysis uses observed decrypted eliciting packets within the correct
connection. Reordering exports have some undecoded packet numbers; one native
Chrome packet also lacks connection identity. Those omissions remain explicit
and are never filled using tuple guesses. Counts under loss are not pure ACK
trigger thresholds. Firefox can drain more input than the engine's bounded
queue; identical native batch boundaries remain unestablished.

`batch-diagnostic.json` comes from separate **intrusive** syscall traces, excluded
from timing references. Chrome's QUIC socket uses `recvmmsg` capacity 45 and
actually returns 45; Surf uses and returns 8. The Chrome fd was correlated with
its connected endpoint before tracing. Aggregate return values and trace hashes
are retained without raw process/socket metadata. Both diagnostic transfers
passed protocol/body checks. Matching syscall capacities is unnecessary for
honoring Chrome's per-datagram ACK threshold.

## Reproduction

See the [manual tools](../../../tools/wirecapture/README.md) and committed plans.
Keep output outside Git, drain tcpdump before SIGINT, retain its exit counters,
and record offloads/qdisc statistics before and after. Use Linux kernel
impairment to preserve native UDP/OOB/batch reads. In an isolated namespace:

```sh
ip link add surfifb type ifb
ip link set surfifb up
tc qdisc add dev eth0 handle ffff: ingress
tc filter add dev eth0 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev surfifb
tc qdisc add dev eth0 root netem limit 10000 delay 20ms loss random 0.25% seed 42
tc qdisc add dev surfifb root netem limit 10000 delay 20ms loss random 0.25% seed 43
```

For reordering in a fresh namespace, use `delay 10ms 2ms distribution normal
reorder 5% 25%` instead of the delay/loss clause, with the same respective seeds.
Pinned direct source URLs and hashes are in the manifest: Chromium 158's packet
reader, QUICHE's response flush, Firefox 160's input loop, Neqo recovery and the
anonymous Alt-Used rule. The [issuer-candidate update procedure](../../../../profiles/chrome/common/INTERMEDIATES.md)
and [verification regressions](../../../tls_certificate_intermediates_test.go)
describe the certificate correction.
