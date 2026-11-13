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

## Chrome origin-level HTTP_1_1_REQUIRED state

The follow-up implementation extends the per-request fallback. Chromium 158's
`SpdySession::OnRstStream` accepts the reset only for an active stream, then
`DoDrainSession` makes the session unavailable, marks the TLS destination and
aborts its other active streams with the same requirement. `OnGoAway` also
drains the entire session for this code, including streams at or below the
advertised LastStreamID. It deliberately sends no GOAWAY in reply.

[HttpServerProperties](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_server_properties.h)
stores at most 100 required servers in a separate LRU set. Lookups refresh its
order. There is no TTL or disk write. The key contains the normalized origin and
NetworkAnonymizationKey, without a proxy identifier. The
[upstream tests](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_server_properties_unittest.cc)
check partitioning, HTTPS/WSS normalization and LRU eviction.

Despite its name, this property only prohibits H2. Chromium explicitly says so
in [HttpStreamPool::CanUseQuic](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_stream_pool.cc)
and `CalculateAllowedAlpns` in
[http_stream_pool_job.cc](https://github.com/chromium/chromium/blob/158.0.8127.18/net/http/http_stream_pool_job.cc).
`FindAvailableSpdySession` ignores existing H2 sessions after a requirement is
recorded. A valid alternative H3 service remains available.

Surf implements this state per built JA TCP transport. Proxy child transports
share the same cache; separate clients are separate network contexts. The key
uses the actual TLS destination, never an overridden request Host. The generic
HTTP engine's `ConnectionErrorPolicy` runs before waking requests, so origin
state is visible before a retry or concurrent request can start. Chrome owns
the code selection and capacity; the engine owns connection retirement.
`HTTP2Settings().HTTP1RequiredCache(n).Set()` exposes the capacity through the
existing nested builder. Chrome desktop/Android and JA.Chrome158 select 100;
Firefox, iOS and generic TLS profiles leave the policy disabled. An explicit
zero selects the previous per-request fallback behavior. Builder mutations
after Build do not alter the created state.

New verified TLS tests cover RST_STREAM and GOAWAY, affected concurrent streams,
idle Preconnect GOAWAY, subsequent Preconnect, keep-alive, LRU hits/eviction,
ports and client isolation, proxy/direct transitions, unrelated error codes,
inactive resets, Host overrides, single-use bodies, public overrides, and
ordered headers/replayable bodies for GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS.
Explicit peer-requested retry remains available after 103; final response
headers expose the body error without replay. A real ECH transition verifies
certificate checks, accepted ECH and HTTP/1 ALPN through the owned ticket cache.
[Independent loopback decoding](../http2_required/README.md) additionally checks
actual ClientHello ALPN lists, the peer RST and the absence of GOAWAY.
An authenticated Alt-Svc case verifies HTTP/3 remains eligible; a controlled
fallback delay isolates eligibility from the connection race. Existing suites
retain normal ALPN/no-ALPN behavior and Firefox's per-request fallback.

These are source checks and actual frame/header observations through controlled
TLS peers. They do not claim a new ordinary native-browser capture of a forced
error on a publicly trusted server, full browser socket-pool scheduling after
LRU eviction, or top-frame partitioning. Surf has no browser document model;
applications needing distinct contexts use independent clients.
