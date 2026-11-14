# Chrome issuer candidates

Chrome advertises Trust Anchor IDs that let a peer omit known intermediate
certificates. `intermediates.pem` contains the 15 additional signed certificates
corresponding to IDs in Surf's current Chrome ClientHello. The other advertised
IDs identify roots. These certificates are **untrusted chain-building candidates**:
the caller's `RootCAs` or system roots still decide trust. No roots are installed,
and no certificates are fetched during a request.

The pinned Chromium 158 root store is version 43. Source URLs, source hashes,
DER hashes and the mapping to advertised IDs are in `intermediates.json`.
Both inputs are Chromium's `net/data/ssl/chrome_root_store/root_store.textproto`
and `additional.certs`; individual `certs/<hash>.pem` URLs are not the source of
these additional certificates.

When updating Chrome:

1. Inspect the new ClientHello's advertised IDs and the pinned root-store source.
2. Select only matching `additional_certs` entries and extract their signed PEM
   certificates from `additional.certs`, preserving manifest order.
3. Verify each DER SHA-256 against `sha256_hex`; retain the new source URLs and
   hashes in the manifest. Review constraints, expiry and root ownership changes.
4. Run `go test ./tests/profiles/chrome ./tests -run 'Intermediate|ElidedChain'`
   and a verified public peer that actually elides its intermediate.

`common.CertificateIntermediates()` returns a fresh pool. Desktop and Android
profiles configure it through the public fluent `CertificateIntermediates`
method. Switching to another profile clears the previous candidates. An
application can replace or clear the candidates after selecting its profile:

```go
client := surf.NewClient().Builder().
    Impersonate().Chrome().
    CertificateIntermediates(myIssuerCandidates).
    SecureTLS().Build().Unwrap()
```

This provides ordinary X.509 chain completion. It does not implement the complete
Chrome Root Store, Chrome's Certificate Transparency or revocation policy, or
direct intermediate trust-anchor semantics.

References: [Chromium root store](https://github.com/chromium/chromium/blob/158.0.8127.18/net/data/ssl/chrome_root_store/root_store.textproto),
[TLS Trust Anchor IDs, intermediate elision](https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-05.html#name-intermediate-elision).
