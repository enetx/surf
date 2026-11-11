# Real ECH inner ClientHello references

The two `chrome-157-tcp-*.json` files pair native Chrome 157.0.8103.51's
`SSL_ENCRYPTED_CLIENT_HELLO` with the first `SSL_HANDSHAKE_MESSAGE_SENT`
ClientHello on the same NetLog socket. Captured on macOS, 2026-11-11, using a
fresh isolated profile and the browser's ordinary Secure DNS preference pointing
to Cloudflare. Certificate verification stayed enabled. There were no TLS,
ECH, QUIC, cipher, certificate or address-override flags.

Each fixture retains only its two ClientHello handshake messages. They contain public
key shares, connection randoms, ECH ciphertext and public endpoint names; no
private keys, session tickets, cookies, account data or NetLog secrets are stored.
The two original Chrome TCP pairs are fresh handshakes. Additional native QUIC
and Firefox pairs are described below. None contain resumption identities.

`tests/profiles/ech/inner_test.go` applies Surf's policy to the actual captured
outer and compares every expanded extension's bytes/order and the cipher order
with the native inner. No GREASE, key-share or trust-anchor normalization is
needed when both halves come from the same connection.

Source checks:

- Chrome 157.0.8103.51's DEPS pins BoringSSL
  `5b83e5d1abf0ae0033ae52ab579d906b67633b2c`.
  [extensions.cc](https://github.com/google/boringssl/blob/5b83e5d1abf0ae0033ae52ab579d906b67633b2c/ssl/extensions.cc#L4379)
  builds literal SNI/ECH/versions before the contiguous compressed block;
  ALPN, ALPS, signatures, trust anchors and certificate compression retain
  their complete outer payloads.
  [handshake_client.cc](https://github.com/google/boringssl/blob/5b83e5d1abf0ae0033ae52ab579d906b67633b2c/ssl/handshake_client.cc#L86)
  limits the inner cipher list to TLS 1.3 plus GREASE in configured order.
- Firefox uses vendored NSS from `FIREFOX_160_0_RELEASE`.
  [tls13ech.c](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13ech.c#L1352)
  places the inner marker first, then private SNI and TLS 1.3 versions in outer
  order, then duplicated extensions in one block.
  [tls13con.c](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13con.c#L6660)
  defines allowed TLS 1.3 extensions, including padding.
  [key selection](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/security/nss/lib/ssl/tls13con.c#L3847)
  retains each private key and looks it up by the server-selected group.

The Firefox 160 TCP and QUIC pairs come from an unmodified official Linux
aarch64 release. Its SHA-512 was checked against Mozilla's release SHA512SUMS.
The full browser ran on Xvfb with a fresh profile, ordinary Secure DNS settings,
and certificate verification enabled. tcpdump recorded real traffic. Wireshark
4.6.9 independently decrypted ECH using stock NSS `ECH_SECRET` / `ECH_CONFIG`
key-log records. Expanded inner fixtures restore the outer legacy session ID
and replace RFC 9849 outer references using decoder raw fields. No secret keys or
resumption tickets are retained in the repository.

Two UDP GSO aggregates required splitting at 1252-byte segment boundaries in an
**analysis copy** with reconstructed IP/UDP envelopes. Wireshark then verified
Initial packet authentication and CRYPTO reassembly. The original pcap's SHA-256
is recorded in each fixture. These fixtures establish TLS bytes and order;
they do not establish wire datagram boundaries, pacing or IP-header parity.

The Chrome QUIC pair uses native `SSL_ENCRYPTED_CLIENT_HELLO` on QUIC_SESSION
234 and the actual UDP payloads on its bound UDP_SOCKET 233. Wireshark independently
reassembled the outer from those payloads. Synthetic envelopes were used solely
for decoding. Its NetLog SHA-256 and extraction details are recorded in the file.

All five fresh pairs compare the complete inner cipher list and every expanded
extension's bytes/order. QUIC tests also compare Firefox's restricted public
parameters with the native outer. These references caught three distinctions:
Firefox TCP keeps its full cipher list; Chrome compresses supported_versions
when the outer already requires TLS 1.3; Neqo retains full transport parameters
only inside ECH. The matching pinned source explains each observed behavior.

Verified local tests separately cover fresh and resumed TCP/QUIC, engine-owned
PSK binders, randomized/omitted outer PSK, HRR, key-group selection, certificate
failures, authenticated retry limits and application bodies. An independent
standard TLS QUIC server verifies equal client/server early traffic secrets;
HRR, changed ALPN and application session veto prevent early-data acceptance.
Native fresh fixtures do not prove full browser resumption or 0-RTT parity.

## HTTPS DNS metadata verification

Surf resolves HTTPS metadata before starting TLS on either transport.
[Chrome 157 SSLConnectJob](https://chromium.googlesource.com/chromium/src/+/157.0.8103.51/net/socket/ssl_connect_job.cc#404)
passes endpoint ECHConfig to the TLS socket.
[Its DNS task](https://chromium.googlesource.com/chromium/src/+/157.0.8103.51/net/dns/host_resolver_dns_task.cc#1137)
starts a supplemental HTTPS timer only after address transactions finish and
omits that timer when the HTTPS response is required.
[Firefox 160](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpConnectionMgr.cpp#L1760)
does not dispatch transactions that are waiting for HTTPS RR when ECH is enabled.
Surf's built-in path starts A/AAAA and HTTPS together and shares completed address
results with Surf's first TCP/QUIC connection. A private default-dialer adapter
identifies ownership; application-supplied DialContext functions keep control of
name resolution and receive their original endpoint. Chromium's opportunistic profile uses
20% of address lookup duration with 5–50 ms bounds, starting after addresses
complete; both secure/insecure defaults are pinned in
[features.cc](https://chromium.googlesource.com/chromium/src/+/157.0.8103.51/net/base/features.cc#90).
Firefox uses no supplemental deadline. Explicit HTTPS callbacks retain their own
timing. DNS transport deadlines, request cancellation and shared-flight cleanup
still apply. Addresses are not cached under the unrelated HTTPS TTL.

Native Chrome NetLog starts A and HTTPS for the target in the same millisecond.
Firefox's independently decoded DoH responses include HTTPS/A/AAAA within one
millisecond. The latter observation does not establish exact query-start times.
A controlled UDP DNS peer withholds all responses until all three query types
arrive, then requires exactly one of each for both browser profiles across H1,
H2 and H3. Separate tests gate address completion, supplemental timer start,
HTTPS completion and cancellation. Native OS resolver internals, DNS caches,
Happy Eyeballs scheduling and wire timing are not claimed to match every platform.

Regression tests delay a valid HTTPS ECH response by 100 ms and require verified
ECH on the first TCP/H3 connection and on subsequent requests. They cover both
profiles, direct forced H3 without dropping DNS metadata, authenticated Alt-Svc
promotion from TCP to H3, caching, cancellation and rejected ECH without a
plaintext retry.

Manual public probes on 2026-11-11 used normal system DNS and normal certificate
verification. `www.cloudflare-quic.com/cdn-cgi/trace` reported HTTP/3,
`ECHAccepted=true`, and `sni=encrypted` for Chrome and Firefox, in automatic and
forced H3 modes. `crypto.cloudflare.com/cdn-cgi/trace` reported HTTP/2 and the
same ECH indicators for both profiles. The latter's HTTPS RR advertises h2;
`www.cloudflare.com` advertises h3/h2 but currently has no ECHConfig. These live
observations are not stable fixtures and do not belong in offline CI assertions.

Additional public probes with `.DNS("8.8.8.8:53")` and
`.DNSOverTLS().Cloudflare()` also accepted ECH on H3. Offline tests verify that
the public DNS setter routes both HTTPS and address queries to the configured
server, before or after the browser selector. TLS transport tests use a trusted
local certificate and reject an untrusted DNS certificate without sending a
plaintext query. Existing stream framing, alias handling and cancellation tests
cover the resolver adapter. An explicit `HTTPSRecordsLookup` callback replaces
the built-in HTTPS query path while retaining the configured address resolver.

## Public traffic verification after the resumption changes

On 2026-11-11, 18 Surf connections to the public Cloudflare QUIC trace endpoint
used normal system DNS and certificate verification: Chrome/Firefox, forced H2,
forced H3 and opt-in H3 early data, three fresh connections per client. All
reported verified ECH and `sni=encrypted`; connections two and three resumed.
A real tcpdump capture independently decoded all 18 outer ClientHellos.
Chrome omitted public PSK, Firefox used public PSK on resumption, and Firefox
QUIC exposed only parameter IDs 11, 15 and 17. Early-data offers and encrypted
0-RTT packets appeared only in the explicitly enabled scenarios. This is a dated
manual observation, not a network-dependent CI requirement.

Authenticated ECH retry is bounded to one new connection. Invalid provider or
private-name certificates, absent retry configs and a second rejection fail
without sending HTTP application data. A retry preserves the original route,
resolver, proxy and request deadline and does not mutate DNS or caller TLS config.

The expanded Linux race run also reproduced an upstream QUIC parameter-pointer
race during 0-RTT stream creation. The existing QUIC fork carries the proposed
upstream correction plus synchronization of application state/datagram snapshots;
its maintenance notes pin the open PR and record its unmerged status. Regression
tests fail under `-race` before the fix and pass afterward. New streams retain
remembered send limits until transport parameters are applied after the handshake.
