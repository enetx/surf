# Chromium 158 HTTP/3 connection coalescing

Reference: native Chromium 158.0.8127.0, macOS arm64 snapshot 1727489.
The relevant session pool, session key, client session and transaction files are
byte-identical at Chromium tags 158.0.8127.0 and 158.0.8127.18. This audit does not
change the Firefox profile or establish native Firefox early-GET acceptance.

## Primary sources and implemented scope

| Behavior | Primary source | Surf behavior |
| --- | --- | --- |
| Exact session first; certificate/privacy checks before IP waiver | [FindExistingSession, CanWaiveIpMatching, HasMatchingIpSession](https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_session_pool.cc), [CanPool](https://github.com/chromium/chromium/blob/158.0.8127.18/net/spdy/spdy_session.cc) | A live confirmed connection has one pool owner. Certificate chains and the new hostname must verify. Same destination, ORIGIN or enabled server NOIP can waive IP matching; otherwise the resolver must match the actual peer IP and port. |
| Isolation includes require_dns_https_alpn | [QuicSessionKey::CanUseForAliasing](https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_session_key.cc) | DNS-only jobs and known-version Alt-Svc/explicit-H3 jobs have separate partitions, including exact-authority lookups. An optional application partition further separates both exact and cross-authority reuse. |
| ORIGIN enabled; 20 distinct valid entries | [OnOriginFrame](https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_chromium_client_session.cc), [RFC 9412](https://www.rfc-editor.org/rfc/rfc9412.html) | Parse bounded entries on the server control stream after SETTINGS, validate the complete frame before publication, ignore invalid/duplicate entries, retain at most 20 by default. Ordinary serialized origins support IDNA, IPv6 and explicit ports. |
| NOIP IP waiver defaults off | [QuicParams](https://github.com/chromium/chromium/blob/158.0.8127.18/net/quic/quic_context.h), [kIgnoreIpMatchingWhenFindingExistingSessions](https://github.com/chromium/chromium/blob/158.0.8127.18/net/base/features.cc) | Chrome advertises ORIGNOIP but does not enable server-NOIP-only reuse by default. IgnoreIPMatching(true) requires NOIP from the current authenticated peer handshake, never an old ticket or the client's own advertisement. |
| Connection options are four-byte tags | [QUICHE transport parameter parser](https://github.com/google/quiche/blob/132bfd90ea370faeacee616c70d10210bb12ba66/quiche/quic/core/crypto/transport_parameters.cc) | Chrome rejects malformed lengths during the handshake even when NOIP-based pooling is disabled; aligned unknown tags are ignored. |
| 421 retry is transaction-local | [HttpNetworkTransaction](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_network_transaction.cc) | Retry once with pooling and Alt-Svc disabled for that attempt. Automatic mode uses the TCP transport; explicit ForceHTTP3 uses a dedicated HTTP/3 attempt. A one-shot upload is not replayed. Subsequent requests may still use the original connection. |

All browser policy lives in Surf. The QUIC fork exposes generic peer-extension
snapshots/validation, bounded control-frame observation and authorized pool reuse.
Default QUIC clients retain their per-authority pool and ignore unknown extensions.

## Native evidence

An ordinary fresh Chromium profile issued no-cors, credentials-omitted,
cache-no-store GETs from about:blank. Flags enabled CDP, a separate profile,
NetLog Everything and TLS key logging. No certificate-verification, QUIC,
origin-mapping or feature override was used.

In the final run the active confirmed session 111 advertised 11 ORIGIN entries.
It carried requests to www.google.com, www.gstatic.com, fonts.gstatic.com,
www.youtube.com and google.com. First gstatic/fonts/youtube requests used H2;
their second requests, after receiving Alt-Svc, reused session 111 over H3.
NetLog explicitly records USE_EXISTING_SESSION for these destinations. Earlier
Google sessions 50/31 include a separate initial session and a browser background
privacy context; they are not conflated with the active shared owner.

The native session's original UDP payloads were reconstructed into an analysis
pcap with the existing echresumption/netlog.mjs tool, then independently decrypted
by TShark 4.6.9. IP/UDP envelopes in this analysis pcap are synthetic. These bytes
establish HTTP/3 requests on one QUIC connection; they establish no native NIC
timing, IP-header or packet-pacing equivalence.

The independent request-field oracle uses the first correctly decoded blocks on
streams 0 and 4 (Google and gstatic). TShark 4.6.9 reports inconsistent later
dynamic-table authority/path values, so those fields are excluded. Later
fonts/youtube/google.com reuse is established by Chromium's NetLog/CDP, rather
than silently treating an inconsistent external decoder as a complete oracle.

observations.json contains sanitized provenance, hashes and decoded findings.
Original NetLogs, profiles, key logs, certificates and raw captures stay private.

## Surf wire regressions

Public tests create real trusted TLS/QUIC peers and decode actual HTTP/3/QPACK.
They cover IP/certificate checks; ORIGIN and NOIP with NXDOMAIN; malformed
parameters; different ports; custom verification/client credentials; independent
clients; SOCKS5 route retention; same/different-authority application partitions;
DNS/Alt-Svc transitions; one-shot and replayable uploads; transaction-local 421;
and GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS and TRACE with ordered user fields.

ORIGIN authorization uses the selected Alt-Svc destination, which can differ
from the request authority. The early cache probe freezes that route together
with its pool partition. A regression reproduced an overly eager origin-only
reuse before this correction; a positive case authorizes the alternative itself.
An explicitly empty transaction-local 421 route still suppresses Alt-Svc.

One request checks every eligible fast ORIGIN/NOIP authorization before DNS.
Fallback DNS results are shared only among that attempt's candidates; a failed
lookup does not poison a later request. Callback errors wrapping REQUEST_REJECTED
and a reset after valid informational headers cannot cause an application replay
or evict another origin's healthy owner. Active response bodies, GOAWAY, closure,
cancellation, preconnect and pool ownership are independently tested in the engine.

An independent Linux loopback tcpdump captures the public regression matrix.
TShark decrypts the capture with optional diagnostic key logging. This checks
encrypted transport and QPACK independently of the peer assertions. Kernel-drop
counts and exact hashes are recorded beside the final findings. An earlier
capture under concurrent compilation dropped packets and is excluded from the
final wire findings.

Reproduce deterministic assertions from Surf's module root:

```sh
go test -race ./tests ./internal/http3 -run 'Coalesc|ApplicationPartition|OriginFrame' -count=5
```

For an independent private capture, set SURF_COALESCING_KEYLOG to a mode-0600
file, start tcpdump on loopback with a sufficient buffer, run the public tests,
wait for the capture to drain and stop tcpdump with SIGINT. Decrypt using
`tshark -r PRIVATE.pcap -o tls.keylog_file:PRIVATE.keys`. Never commit secrets.

## Fluent configuration

Chrome desktop/Android profiles enable the verified coalescing/ORIGIN policy.
A plain client remains dedicated unless the application enables it:

```go
client := surf.NewClient().Builder().SecureTLS().
    HTTP3Settings().
    ConnectionCoalescing(true).
    OriginFrames(true).
    OriginFrameLimit(20).
    IgnoreIPMatching(false).
    Set().
    Build().Unwrap()
defer client.Close()
```

Coalescing requires verified TLS. A profile used with insecure verification keeps
dedicated connections; calling SecureTLS() enables ordinary certificate validation.

ConnectionPoolPartition accepts a concurrency-safe function of the context and
authority for applications with additional tenant/site isolation. It applies even
when coalescing is disabled. The browser discovery partition remains mandatory.
OnOrigin observes newly learned canonical origins after a complete frame; its
callback must not block or reenter the connection.

## Limits retained in BROWSER_PARITY.md

- Surf has one network context per built client plus optional application keys;
  it does not construct browser top-frame NetworkAnonymizationKeys.
- Connections with configured client credentials, insecure verification or custom
  verification callbacks remain dedicated. Chromium's complete CT/pinning/client
  certificate policy is not reproduced by a second VerifyHostname call.
- Cross-authority reuse waits for the current verified handshake. Browser aliasing
  before confirmation and exact multi-candidate selection order are not claimed.
- Invalid ORIGIN strings outside ordinary serialized origins can differ from
  permissive GURL normalization. No full GURL implementation is introduced.
- Cold public protocol choice is a separate scope: Chromium has proactive QUIC
  eligibility and browser history. A Surf Mac DNS-only owner can legitimately
  coalesce another DNS-only job while Chromium's known-H3 owner cannot. The public
  Docker sample selected H2 throughout; it does not validate H3 pooling.
- These tests establish the recorded pool decisions, not complete browser
  connection migration, document resource scheduling or native NIC timing.
