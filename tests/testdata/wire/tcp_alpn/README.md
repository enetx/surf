# TCP ALPN selection: Chromium 158 and Firefox 160

This audit checks protocol selection and connection ownership. It does not infer
browser behavior from an anti-bot vendor's response status.

## Primary sources

- Chromium 158.0.8127.18
  [AttemptManager::OnTcpBasedAttemptComplete](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_stream_pool_attempt_manager.cc)
  reads the negotiated protocol from the completed socket. HTTP/1 sockets go to
  `CreateTextBasedStreamAndNotify`, then
  [Group::CreateTextBasedStream](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_stream_pool_group.cc)
  moves that same socket into `HttpBasicStream`. The legacy
  [Job::DoCreateStream](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_stream_factory_job.cc)
  also moves the existing connection into `HttpBasicStream`. ALPN selection does
  not require another TLS handshake or an HTTP/1-only ClientHello.
- Chromium's
  [SpdySession::DoDrainSession](https://github.com/chromium/chromium/blob/158.0.8127.18/net/spdy/spdy_session.cc)
  marks the origin HTTP/1-required after `HTTP_1_1_REQUIRED`.
  [HttpNetworkTransaction::HandleHttp11Required](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_network_transaction.cc)
  restarts the request, while
  [HttpServerProperties::MaybeForceHTTP11](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_server_properties.cc)
  restricts ALPN for subsequent connections. This is distinct from an ordinary
  ALPN answer selecting HTTP/1.
- Firefox 160.0
  [nsHttpConnection::HandshakeDoneInternal](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpConnection.cpp)
  starts SPDY only when the negotiated value matches HTTP/2, then completes NPN
  setup and resumes sending on the existing connection. There is no redial just
  because the selected protocol is HTTP/1 or ALPN is absent.
- Firefox's
  [Http2Session reset / GOAWAY handling](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/Http2Session.cpp)
  calls `DisableSpdy` on restarted transactions for `HTTP_1_1_REQUIRED`.
  [nsHttpTransaction::DisableSpdy](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpTransaction.cpp)
  sets `NS_HTTP_DISALLOW_SPDY` and `NoSpdy` on that transaction's connection info;
  [TlsHandshaker::InitSSLParams](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/TlsHandshaker.cpp)
  excludes HTTP/2 when the transaction disallows it.

## Reproduced regression and PR #76

The original Surf implementation closed a successfully negotiated HTTP/1 TLS
connection, returned `errALPNNotH2`, and dialed again with HTTP/1-only ALPN.
A verified local peer observed **two ClientHellos**, including one without `h2`.
This confirms the protocol bug reported in PR #76. The reported Akamai outcomes
are observations by the PR author; this audit does not independently attribute
those responses to a specific anti-bot rule.

The PR's request-local connection holder fixes its single-GET example, including
an actually absent ALPN extension. Additional regressions exposed limitations:

| Scenario | PR implementation observed | Required behavior |
| --- | --- | --- |
| Three sequential HTTP/1 requests | Three handshakes, one extra negotiation for every request | Reuse the eligible pooled connection |
| Two concurrent requests to an HTTP/1 peer | A later ClientHello omits `h2` | Additional connections retain normal ALPN |
| One-shot POST without `GetBody` | Fails before the server receives its body | Negotiation must not require body replay |
| Explicit Preconnect then GET | Three handshakes in the ordinary request path | Send on the already prepared connection |

The concurrency fixture holds both requests at the peer until both are received,
so it cannot accidentally pass by serially reusing an idle HTTP/1 connection.
Only requests sharing one origin and TLS configuration participate.

Earlier tests checked successful response status and the final HTTP version.
One proxy regression explicitly expected two tunnels, thereby preserving the
redial rather than testing browser parity. The previous no-ALPN fixture also used
`NextProtos: nil`; `httptest.StartTLS` fills nil with `http/1.1`. The new fixture
uses a non-nil empty list and asserts an empty negotiated protocol.

## Implementation and checks

Surf uses the linked HTTP/1 + HTTP/2 transport's existing connection pool. The
HTTP adapter preserves an HTTP/1 socket returned by the external TLS dial when
both protocols are enabled. HTTP/2 dial coalescing stops waiting for a leader's
response when the negotiated connection cannot multiplex requests.

`http.Transport.PrepareHeaders` prepares a private header map for the actual
selected protocol. Both new and cached HTTP/2 connections use it. Header
validation, request-body ownership and caller cancellation remain with the
transport. The response retains the prepared request's metadata, which is needed
for multi-hop redirects after a POST body is dropped. A nil callback leaves the
native header path unchanged. Browser settings remain in Surf.

Tests cover both browser profiles, explicit HTTP/1 and absent ALPN, keep-alive,
one-shot bodies, Preconnect, concurrent requests, TLS/certificate errors and
cancellation. Existing suites check H1/H2/H3 ordered headers, Client Hints,
pseudo headers, redirects, HTTP/2 reset/GOAWAY fallback and safe resend behavior.
These are controlled, verified TLS peer observations and primary-source checks;
no new native browser NIC capture or anti-bot success rate is claimed here.

## Separately tracked scope

Chrome's origin-level `HTTP_1_1_REQUIRED` cache is broader than Surf's existing
per-request fallback. It is tracked separately in `BROWSER_PARITY.md`; the ALPN
fix does not turn a normal HTTP/1 ALPN answer into a persistent origin downgrade.
