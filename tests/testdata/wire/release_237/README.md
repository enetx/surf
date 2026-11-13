# Surf v1.0.237 migration and release validation

The source tree, committed browser references and pending ALPN fixes survived the
move to the new Mac. Old `/tmp` captures were absent. The following fresh checks
were performed rather than treating the missing raw data as locally available.

## Environment and independent observations

- Go 1.27.4 on macOS arm64 and Linux arm64; Node 26.13.1.
- The Linux test image is defined in `tests/tools/Dockerfile`. Host TShark 4.6.9
  decoded the captures; the image's packaged TShark reports 4.6.4.
- Chromium 158.0.8127.0 snapshot 1727489 was downloaded again. Its archive SHA-256
  matches `ech/resumption/chromium-158-audit.json`. Installed Firefox reports 160.0.
- Ordinary fresh-profile navigations selected HTTP/3 through normal Alt-Svc on
  the public endpoint. Firefox matched every compared normalized TLS, SETTINGS,
  header/value/order and transport-parameter field. Chromium matched the same
  stable wire fields and header order; its unbranded brand list differs from
  the explicit Google Chrome identity in Surf. QUIC parameter order is randomized.
- Fresh native Chromium TCP and QUIC resumed transcripts independently verified
  ECH acceptance and selected PSK before redaction. Native UDP envelopes were
  reconstructed from original NetLog payloads; no NIC timing inference is made.
- Surf's final Linux eth0 capture contains 254 packets, all 254 packets reported
  by the capture filter, with zero kernel drops. Three Chrome TCP, three Chrome
  QUIC and three Firefox QUIC connections establish verified ECH. The six repeat
  connections resume. All six complete resumed pairs independently verify ECH
  and selected PSK; all four QUIC pairs offer and accept early request data.
  Stable inner fingerprints match the browser references.

Final private Surf pcap SHA-256: `885d37278263fb35c73e5d60e7acd4911a9e2b4e9f1e58a776ad70754ad74827`.
Raw pcaps, NetLogs, keys, profiles and unredacted ticket pairs stay outside Git.
Endpoint snapshots are not packet-timing evidence.

## Findings and limits

[The ALPN audit](../tcp_alpn/README.md) explains PR #76, the Chromium/Firefox
source paths, connection continuity and why previous tests missed the redial.
It also distinguishes explicit HTTP_1_1_REQUIRED from normal ALPN selection.
Chrome's broader origin-level requirement cache remains separately tracked.

A deterministic interleaving test additionally reproduced loss of a valid
single-use ticket published during version/RTT lookup. The fix checks live
origin ownership after the application cache returns, preserving exactly-once
consumption and foreign-origin rejection. The old implementation fails the new
regression. This proves the local defect; it does not establish the cause of
one earlier public probe's missing third resumption. A subsequent full capture
and the final nine-connection capture both completed every expected resumption.

The fresh native Chromium QUIC sample has two early packets, including two
with control data and one with request data. Surf's two resumed samples have
one and two early packets respectively. The native requests are opaque fetches
on macOS; Surf uses direct API GETs on Linux. These are different request and OS
contexts. Packet-count parity and application scheduling remain unverified;
matching TLS fingerprints do not imply identical 0-RTT packet packing.

Go 1.27.3 → 1.27.4 changes only `server.go` in the retained HTTP source tree.
The upstream MaxBytesReader concurrency fix was transferred and its regression
adapted to the public test package. The old code fails with the race detector;
the corrected code passes. HTTP v1.0.39 passed race tests, vet and maintenance
checks on Linux, macOS and Windows before publication.
