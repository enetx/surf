# Public certificate-chain regression

`storage-googleapis-com.pem` is the single leaf certificate received by Surf's
Chrome QUIC profile from `storage.googleapis.com` on 2026-11-14. Its DER SHA-256 is
`42330480d5f33fb5a3f7abb092802ab5aaf01f173cadd69c3156faa56636c4c5`.
The peer elided WE2 in response to advertised Trust Anchor ID `d679090b`.
The verified native Chrome 158 Linux download succeeded before the Surf fix;
the same verified Surf request failed with `x509: certificate signed by unknown
authority`. Keeping the extension and supplying untrusted WE2 candidates fixed it.

`gts-root-r4.pem` comes from Chromium 158.0.8127.18's
[`root_store.certs`](https://github.com/chromium/chromium/blob/158.0.8127.18/net/data/ssl/chrome_root_store/root_store.certs).
Its DER SHA-256 is `349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d`.
The offline test uses a fixed capture-era time and an explicit pool containing
only that root; no network access, operating-system trust assumption or private
key is required. Candidates without the explicit trusted root must still fail.

The runtime candidate bundle and pinned source hashes live in
[`profiles/chrome/common`](../../../profiles/chrome/common/INTERMEDIATES.md).
Generated local chains separately test expiry, CA constraints, hostname checks,
pool ownership, profile replacement and H1/H2/H3 proxy transport inheritance.
