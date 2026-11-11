# Real ECH inner ClientHello references

The two `chrome-157-tcp-*.json` files pair native Chrome 157.0.8103.51's
`SSL_ENCRYPTED_CLIENT_HELLO` with the first `SSL_HANDSHAKE_MESSAGE_SENT`
ClientHello on the same NetLog socket. Captured on macOS, 2026-11-11, using a
fresh isolated profile and the browser's ordinary Secure DNS preference pointing
to Cloudflare. Certificate verification stayed enabled. There were no TLS,
ECH, QUIC, cipher, certificate or address-override flags.

Only the two ClientHello handshake messages are retained. They contain public
key shares, connection randoms, ECH ciphertext and public endpoint names; no
private keys, session tickets, cookies, account data or NetLog secrets are stored.
These are fresh TCP handshakes, not resumption or decrypted QUIC captures.

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

Firefox policy assertions are **source-derived**. Existing Firefox outer wire
fixtures do not establish a decrypted Firefox inner reference. Local verified
TCP/QUIC handshakes test ECH acceptance, payload delivery, extension sets,
cipher preference, selected groups and HRR for both profiles. These checks do
not establish complete browser parity for resumption or 0-RTT. The inherited
custom-PSK + real-ECH rejection remains explicit.

## HTTPS DNS metadata verification

Surf resolves HTTPS metadata before starting TLS on either transport.
[Chrome 157 SSLConnectJob](https://chromium.googlesource.com/chromium/src/+/157.0.8103.51/net/socket/ssl_connect_job.cc#404)
passes endpoint ECHConfig to the TLS socket.
[Its DNS task](https://chromium.googlesource.com/chromium/src/+/157.0.8103.51/net/dns/host_resolver_dns_task.cc#1137)
starts a supplemental HTTPS timer only after address transactions finish and
omits that timer when the HTTPS response is required.
[Firefox 160](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_160_0_RELEASE/netwerk/protocol/http/nsHttpConnectionMgr.cpp#L1760)
does not dispatch transactions that are waiting for HTTPS RR when ECH is enabled.
Surf's standalone HTTPS lookup uses DNS transport deadlines and cancellation of
its request waiters. This is not a reproduction of Chromium's combined A/AAAA/
HTTPS task timing. It removes the previous fixed 50 ms deadline from query start.

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
