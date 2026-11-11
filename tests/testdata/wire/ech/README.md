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
